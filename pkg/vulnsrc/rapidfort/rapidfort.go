package rapidfort

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rapidfortDir = "rapidfort"

	// platformFormat is the DB bucket name for a given (base OS, distro version).
	// The layout MUST match trivy-rf/pkg/detector/ospkg/rapidfort/rapidfort.go's
	// platformFormat constant.
	platformFormat = "rapidfort %s %s"
)

var (
	source = types.DataSource{
		ID:   vulnerability.Rapidfort,
		Name: "RapidFort Security Advisories",
		URL:  "https://github.com/rapidfort/security-advisories",
	}

	// supportedOSes maps the on-disk directory name to the upstream SourceID
	// recorded on the DataSource's BaseID field.
	// Debian and Oracle intentionally excluded for the first production release.
	supportedOSes = map[string]types.SourceID{
		"ubuntu": vulnerability.Ubuntu,
		"alpine": vulnerability.Alpine,
		"redhat": vulnerability.RedHat,
	}
)

type VulnSrc struct {
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("rapidfort"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

// Update walks <dir>/vuln-list/rapidfort/{os}/{version}/*.json and writes each
// advisory into the trivy-db bucket layout that trivy-rf's rapidfort detector
// reads at scan time: bucket "rapidfort {os} {version}" → package name → CVE ID.
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rapidfortDir)
	eb := oops.In("rapidfort").With("root_dir", rootDir)

	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		vs.logger.Info("RapidFort directory not found; skipping", "path", rootDir)
		return nil
	}

	// platform -> pkgName -> cveID -> Advisory (writes to advisory-detail bucket)
	advisories := map[string]map[string]map[string]types.Advisory{}
	// cveID -> VulnerabilityDetail (writes to vulnerability-detail bucket).
	// De-duped by CVE ID: the same CVE may appear in many (platform,pkg) files;
	// per-CVE title/description/severity should not diverge, so first write wins.
	vulnDetails := map[string]types.VulnerabilityDetail{}
	dataSources := map[string]types.DataSource{}

	osEntries, err := os.ReadDir(rootDir)
	if err != nil {
		return eb.Wrapf(err, "read rapidfort dir")
	}

	for _, osEntry := range osEntries {
		if !osEntry.IsDir() {
			continue
		}
		osName := osEntry.Name()
		baseID, ok := supportedOSes[osName]
		if !ok {
			vs.logger.Warn("Unsupported OS directory; skipping", "os", osName)
			continue
		}

		osDir := filepath.Join(rootDir, osName)
		versionEntries, err := os.ReadDir(osDir)
		if err != nil {
			return eb.With("os", osName).Wrapf(err, "read os dir")
		}

		for _, vEntry := range versionEntries {
			if !vEntry.IsDir() {
				continue
			}
			version := vEntry.Name()
			platform := fmt.Sprintf(platformFormat, osName, version)
			dataSources[platform] = types.DataSource{
				ID:     source.ID,
				BaseID: baseID,
				Name:   source.Name,
				URL:    source.URL,
			}

			pkgDir := filepath.Join(osDir, version)
			if err := vs.ingestVersionDir(pkgDir, platform, advisories, vulnDetails); err != nil {
				return eb.With("os", osName).With("version", version).Wrap(err)
			}
		}
	}

	if len(advisories) == 0 {
		vs.logger.Info("No RapidFort advisories found")
		return nil
	}

	return eb.Wrap(vs.save(advisories, vulnDetails, dataSources))
}

func (vs VulnSrc) ingestVersionDir(
	pkgDir, platform string,
	out map[string]map[string]map[string]types.Advisory,
	vulnDetails map[string]types.VulnerabilityDetail,
) error {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return oops.Wrapf(err, "read version dir")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(pkgDir, entry.Name())
		pa, err := decodePackageAdvisory(path)
		if err != nil {
			return oops.With("file", path).Wrapf(err, "decode advisory file")
		}
		if pa.PackageName == "" {
			vs.logger.Warn("Missing package_name; skipping", "file", path)
			continue
		}

		pkgBucket := out[platform]
		if pkgBucket == nil {
			pkgBucket = map[string]map[string]types.Advisory{}
			out[platform] = pkgBucket
		}
		cveBucket := pkgBucket[pa.PackageName]
		if cveBucket == nil {
			cveBucket = map[string]types.Advisory{}
			pkgBucket[pa.PackageName] = cveBucket
		}

		for cveID, cve := range pa.Advisories {
			cveBucket[cveID] = buildAdvisory(cve)
			if _, seen := vulnDetails[cveID]; !seen {
				vulnDetails[cveID] = buildVulnDetail(cve)
			}
		}
	}
	return nil
}

func decodePackageAdvisory(path string) (PackageAdvisory, error) {
	f, err := os.Open(path)
	if err != nil {
		return PackageAdvisory{}, err
	}
	defer f.Close()

	var pa PackageAdvisory
	if err := json.NewDecoder(f).Decode(&pa); err != nil {
		return PackageAdvisory{}, err
	}
	return pa, nil
}

// buildVulnDetail extracts per-CVE metadata (title/description/severity) that
// Trivy uses when resolving severity and human-readable text at scan time.
// This also ensures the `vulnerability-detail` bucket exists — trivy-db's
// cleanup step unconditionally deletes it, and bolt errors on delete when
// the bucket is missing.
func buildVulnDetail(cve CVEEntry) types.VulnerabilityDetail {
	return types.VulnerabilityDetail{
		Severity:    parseSeverity(cve.Severity),
		Title:       cve.Title,
		Description: cve.Description,
	}
}

// buildAdvisory converts a CVEEntry into the types.Advisory shape that
// trivy-rf's rapidfort detector expects. Identifiers are preserved in
// Advisory.Custom under the key "identifiers", indexed 1:1 with VulnerableVersions.
func buildAdvisory(cve CVEEntry) types.Advisory {
	adv := types.Advisory{
		Severity: parseSeverity(cve.Severity),
	}

	seenFixed := map[string]struct{}{}
	identifiers := make([]string, 0, len(cve.Events))
	anyIdentifier := false

	for _, ev := range cve.Events {
		constraint := eventToConstraint(ev)
		if constraint == "" {
			continue
		}
		adv.VulnerableVersions = append(adv.VulnerableVersions, constraint)
		identifiers = append(identifiers, ev.Identifier)
		if ev.Identifier != "" {
			anyIdentifier = true
		}

		if ev.Fixed != "" {
			if _, dup := seenFixed[ev.Fixed]; !dup {
				adv.PatchedVersions = append(adv.PatchedVersions, ev.Fixed)
				seenFixed[ev.Fixed] = struct{}{}
			}
		}
	}

	if anyIdentifier {
		adv.Custom = map[string]any{"identifiers": identifiers}
	}
	return adv
}

// eventToConstraint emits constraints in the "no space between op and version"
// form because trivy-rf's version.NewConstraints splits on whitespace when no
// comma is present (see pkg/detector/ospkg/version/constraint.go splitConstraints).
// A single-range constraint like ">= X" would otherwise be misread as two tokens
// and rejected, causing the CVE to be silently marked not-vulnerable.
func eventToConstraint(ev Event) string {
	switch {
	case ev.Introduced != "" && ev.Fixed != "":
		return fmt.Sprintf(">=%s, <%s", ev.Introduced, ev.Fixed)
	case ev.Introduced != "":
		return fmt.Sprintf(">=%s", ev.Introduced)
	case ev.Fixed != "":
		return fmt.Sprintf("<%s", ev.Fixed)
	}
	return ""
}

func parseSeverity(s string) types.Severity {
	if s == "" {
		return types.SeverityUnknown
	}
	if sev, err := types.NewSeverity(strings.ToUpper(s)); err == nil {
		return sev
	}
	return types.SeverityUnknown
}

func (vs VulnSrc) save(
	advisories map[string]map[string]map[string]types.Advisory,
	vulnDetails map[string]types.VulnerabilityDetail,
	dataSources map[string]types.DataSource,
) error {
	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for platform, ds := range dataSources {
			if err := vs.dbc.PutDataSource(tx, platform, ds); err != nil {
				return oops.With("platform", platform).Wrapf(err, "put data source")
			}
		}
		for cveID, detail := range vulnDetails {
			if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, detail); err != nil {
				return oops.With("cve", cveID).Wrapf(err, "put vulnerability detail")
			}
		}
		for platform, pkgs := range advisories {
			for pkgName, cves := range pkgs {
				for cveID, adv := range cves {
					if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platform}, adv); err != nil {
						return oops.With("platform", platform).With("pkg", pkgName).With("cve", cveID).
							Wrapf(err, "put advisory detail")
					}
					if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
						return oops.With("cve", cveID).Wrapf(err, "put vulnerability id")
					}
				}
			}
		}
		return nil
	})
}

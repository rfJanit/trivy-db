package rapidfort

// PackageAdvisory is the on-disk JSON produced by vuln-list-update's rapidfort target.
// One file per (os, distro-version, package) at:
//
//	<cache-dir>/rapidfort/{os}/{version}/{package}.json
type PackageAdvisory struct {
	PackageName   string              `json:"package_name"`
	DistroVersion string              `json:"distro_version"`
	Advisories    map[string]CVEEntry `json:"advisories"` // cveID -> CVEEntry
}

// CVEEntry describes a single CVE affecting one package on one distro version.
// The Events field carries version ranges; each event may optionally carry
// an Identifier ("el9", "fc39", "rf", ...) used by trivy-rf's rapidfort detector
// to disambiguate cross-distro RPM ranges.
type CVEEntry struct {
	CVEID       string  `json:"cve_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Status      string  `json:"status"`
	Events      []Event `json:"events"`
}

// Event describes one vulnerable version range. Introduced+Fixed produce a
// closed interval; either one alone produces a half-open range. Identifier
// tags the range with a distro-specific marker (empty for ubuntu/alpine/debian).
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

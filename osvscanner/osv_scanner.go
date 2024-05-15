package osvscanner

import (
	"errors"
	"fmt"
	"web-scan-worker/internal/models"
	"web-scan-worker/osvscanner/gitParser"
	"web-scan-worker/osvscanner/osv"

	"github.com/google/go-github/v62/github"
)

type scannedPackage struct {
	PURL      string
	Name      string
	Ecosystem models.Ecosystem
	Commit    string
	Version   string
	Source    models.SourceInfo
	DepGroups []string
}

var ErrAPIFailed = errors.New("API query failed")

// Загружаем, идентифицируем и парсим lock-файл
func scanLockfile(file gitParser.DepFile) ([]scannedPackage, error) {
	parsedLockfile, err := gitParser.ExtractDeps(file)

	if err != nil {
		return nil, err
	}

	parsedAsComment := ""

	parsedAsComment = fmt.Sprintf("as a %s ", parsedLockfile.ParsedAs)

	fmt.Printf(
		"Scanned %s file %sand found %d %s\n",
		file.Path,
		parsedAsComment,
		len(parsedLockfile.Packages),
		"packages",
	)

	packages := make([]scannedPackage, len(parsedLockfile.Packages))
	for i, pkgDetail := range parsedLockfile.Packages {
		packages[i] = scannedPackage{
			Name:      pkgDetail.Name,
			Version:   pkgDetail.Version,
			Commit:    pkgDetail.Commit,
			Ecosystem: pkgDetail.Ecosystem,
			DepGroups: pkgDetail.DepGroups,
			Source: models.SourceInfo{
				Path: file.Path,
				Type: "lockfile",
			},
		}
	}

	return packages, nil
}

// Perform osv scanner action, with optional reporter to output information
func DoScan(files []github.RepositoryContent, userInfo gitParser.UserInfo) (models.VulnerabilityResults, error) {
	scannedPackages := []scannedPackage{}

	for _, file := range files {
		content, _ := file.GetContent()
		depFile := gitParser.DepFile{
			Name:    file.GetName(),
			Path:    file.GetPath(),
			Content: string(content),
		}
		pkgs, err := scanLockfile(depFile)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}
		scannedPackages = append(scannedPackages, pkgs...)
	}

	if len(scannedPackages) == 0 {
		return models.VulnerabilityResults{}, errors.New("no packages found in scan")
	}

	filteredScannedPackages := filterUnscannablePackages(scannedPackages)

	if len(filteredScannedPackages) != len(scannedPackages) {
		fmt.Printf("Filtered %d local package/s from the scan.\n", len(scannedPackages)-len(filteredScannedPackages))
	}

	vulnsResp, err := makeRequest(filteredScannedPackages)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	results := buildVulnerabilityResults(filteredScannedPackages, vulnsResp)

	return results, nil
}

// filterUnscannablePackages removes packages that don't have enough information to be scanned
// e,g, local packages that specified by path
func filterUnscannablePackages(packages []scannedPackage) []scannedPackage {
	out := make([]scannedPackage, 0, len(packages))
	for _, p := range packages {
		switch {
		// If none of the cases match, skip this package since it's not scannable
		case p.Ecosystem != "" && p.Name != "" && p.Version != "":
		case p.Commit != "":
		case p.PURL != "":
		default:
			continue
		}
		out = append(out, p)
	}

	return out
}

func makeRequest(
	packages []scannedPackage) (*osv.HydratedBatchedResponse, error) {
	// Make OSV queries from the packages.
	var query osv.BatchedQuery
	for _, p := range packages {
		switch {
		// Prefer making package requests where possible.
		case p.Ecosystem != "" && p.Name != "" && p.Version != "":
			query.Queries = append(query.Queries, osv.MakePkgRequest(models.PackageDetails{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: p.Ecosystem,
			}))
		case p.Commit != "":
			query.Queries = append(query.Queries, osv.MakeCommitRequest(p.Commit))
		case p.PURL != "":
			query.Queries = append(query.Queries, osv.MakePURLRequest(p.PURL))
		default:
			return nil, fmt.Errorf("package %v does not have a commit, PURL or ecosystem/name/version identifier", p)
		}
	}

	if osv.RequestUserAgent == "" {
		osv.RequestUserAgent = "web-scan"
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("%w: osv.dev query failed: %w", ErrAPIFailed, err)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("%w: failed to hydrate OSV response: %w", ErrAPIFailed, err)
	}

	return hydratedResp, nil
}

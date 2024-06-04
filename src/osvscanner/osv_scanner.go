package osvscanner

import (
	"errors"
	"fmt"
	"math"
	"web-scan-worker/src/osvscanner/gitParser"
	"web-scan-worker/src/osvscanner/models"
	"web-scan-worker/src/osvscanner/osv"

	"github.com/google/go-github/v62/github"
)

type scannedPackage struct {
	Name      string
	Ecosystem models.Ecosystem
	Version   string
	Source    models.SourceInfo
	DepGroups []string
}

var ErrAPIFailed = errors.New("ошибка API запроса")

func roundup(value float64) float64 {
	factor := math.Pow(10, 1) // 10^1 = 10
	return math.Ceil(value*factor) / factor
}

func ParseSeverityCategory(value float64) string {
	value = roundup(value)
	if value >= 0.0 && value <= 3.9 {
		return "Low"
	}
	if value >= 4.0 && value <= 6.9 {
		return "Moderate"
	}
	if value >= 7.0 && value <= 10 {
		return "High"
	}

	fmt.Println("Оценка вне допустимых границ:", value)
	return "High"
}

// Загружаем, идентифицируем и парсим lock-файл
func scanLockfile(file gitParser.DepFile) ([]scannedPackage, error) {
	parsedLockfile, err := gitParser.ExtractDeps(file)

	if err != nil {
		return nil, err
	}

	parsedAsComment := ""

	parsedAsComment = fmt.Sprintf("как %s ", parsedLockfile.ParsedAs)

	fmt.Printf(
		"Файл %s успешно просканирован %s- найдено %d %s\n",
		file.Path,
		parsedAsComment,
		len(parsedLockfile.Packages),
		"пакетов",
	)

	packages := make([]scannedPackage, len(parsedLockfile.Packages))
	for i, pkgDetail := range parsedLockfile.Packages {
		packages[i] = scannedPackage{
			Name:      pkgDetail.Name,
			Version:   pkgDetail.Version,
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

// Провести OSV-сканирование
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
		return models.VulnerabilityResults{}, nil
	}

	filteredScannedPackages := filterUnscannablePackages(scannedPackages)

	if len(filteredScannedPackages) != len(scannedPackages) {
		fmt.Printf("отфильтровано %d локальных пакетов из сканирования.\n", len(scannedPackages)-len(filteredScannedPackages))
	}

	vulnsResp, err := makeRequest(filteredScannedPackages)
	if err != nil {
		return models.VulnerabilityResults{}, err
	}

	results := buildVulnerabilityResults(filteredScannedPackages, vulnsResp)

	return results, nil
}

// Фильтр пакетов, о которых недостаточно информации для проверки
func filterUnscannablePackages(packages []scannedPackage) []scannedPackage {
	out := make([]scannedPackage, 0, len(packages))
	for _, p := range packages {
		switch {
		// If none of the cases match, skip this package since it's not scannable
		case p.Ecosystem != "" && p.Name != "" && p.Version != "":
		default:
			continue
		}
		out = append(out, p)
	}

	return out
}

// Сделать запрос к OSV
func makeRequest(
	packages []scannedPackage) (*osv.HydratedBatchedResponse, error) {
	var query osv.BatchedQuery
	for _, p := range packages {
		switch {
		case p.Ecosystem != "" && p.Name != "" && p.Version != "":
			query.Queries = append(query.Queries, osv.MakePkgRequest(models.PackageDetails{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: p.Ecosystem,
			}))
		default:
			return nil, fmt.Errorf("пакет %v не содержит ecosystem/name/version идентификаторы", p)
		}
	}

	if osv.RequestUserAgent == "" {
		osv.RequestUserAgent = "web-scan"
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("%w: ошибка запроса к osv.dev: %w", ErrAPIFailed, err)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("%w: ошибка упаковки OSV ответа: %w", ErrAPIFailed, err)
	}

	return hydratedResp, nil
}

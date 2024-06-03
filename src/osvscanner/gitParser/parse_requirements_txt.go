package gitParser

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"
	"web-scan-worker/src/internal/cachedregexp"
	"web-scan-worker/src/osvscanner/models"

	"golang.org/x/exp/maps"
)

const PipEcosystem models.Ecosystem = "PyPI"

// Парсинг строки
func parseLine(line string) models.PackageDetails {
	var constraint string
	name := line

	version := "0.0.0"

	if strings.Contains(line, "==") {
		constraint = "=="
	}

	if strings.Contains(line, ">=") {
		constraint = ">="
	}

	if strings.Contains(line, "~=") {
		constraint = "~="
	}

	if strings.Contains(line, "!=") {
		constraint = "!="
	}

	if constraint != "" {
		unprocessedName, unprocessedVersion, _ := strings.Cut(line, constraint)
		name = strings.TrimSpace(unprocessedName)

		if constraint != "!=" {
			version, _, _ = strings.Cut(strings.TrimSpace(unprocessedVersion), " ")
		}
	}

	return models.PackageDetails{
		Name:      normalizedRequirementName(name),
		Version:   version,
		Ecosystem: PipEcosystem,
		CompareAs: PipEcosystem,
	}
}

// normalizedName гарантирует, что имя пакета нормализовано в соответствии с PEP-0503,
// а затем удаляет синтаксис «добавленной поддержки», если он присутствует.
//
// Это сделано для того, чтобы мы не пропустили никаких рекомендаций, поскольку,
// хотя спецификация OSV гласит, что для рекомендаций следует использовать нормализованное имя,
// в настоящее время в OSV базах данных это не так, а сам _and_ Pip поддерживает
// ненормализованные имена в requirements.txt, поэтому нам нужно нормализовать обе стороны,
// чтобы исключить ложноотрицательные результаты.
//
// Вполне возможно, что это приведет к некоторым ложным срабатываниям, но это лучше,
// чем ложноотрицательные, и с этим можно справиться, когда/если это действительно произойдет.
func normalizedRequirementName(name string) string {
	// per https://www.python.org/dev/peps/pep-0503/#normalized-names
	name = cachedregexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, "[")

	return name
}

// Удаляем комментарии
func removeComments(line string) string {
	var re = cachedregexp.MustCompile(`(^|\s+)#.*$`)

	return strings.TrimSpace(re.ReplaceAllString(line, ""))
}

// Проверка на то, является ли строка подходящей
func isNotRequirementLine(line string) bool {
	return line == "" ||
		// флаги
		strings.HasPrefix(line, "-") ||
		// ссылки на файлы
		strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "http://") ||
		// пути до файлов
		strings.HasPrefix(line, ".") ||
		strings.HasPrefix(line, "/")
}

// Проверяем, заканчивается ли строка нечётным количеством обратных косых черт, то есть последняя не экранируется
func isLineContinuation(line string) bool {
	var re = cachedregexp.MustCompile(`([^\\]|^)(\\{2})*\\$`)

	return re.MatchString(line)
}

// Парсинг файла requirements.txt
func ParseRequirementsTxt(depFile DepFile) ([]models.PackageDetails, error) {
	packages := map[string]models.PackageDetails{}

	group := strings.TrimSuffix(filepath.Base(depFile.Path), filepath.Ext(depFile.Path))
	hasGroup := func(groups []string) bool {
		for _, g := range groups {
			if g == group {
				return true
			}
		}

		return false
	}

	scanner := bufio.NewScanner(strings.NewReader(depFile.Content))
	for scanner.Scan() {
		line := scanner.Text()

		for isLineContinuation(line) {
			line = strings.TrimSuffix(line, "\\")

			if scanner.Scan() {
				line += scanner.Text()
			}
		}

		line = removeComments(line)

		if isNotRequirementLine(line) {
			continue
		}

		detail := parseLine(line)
		key := detail.Name + "@" + detail.Version
		if _, ok := packages[key]; !ok {
			packages[key] = detail
		}
		d := packages[key]
		if !hasGroup(d.DepGroups) {
			d.DepGroups = append(d.DepGroups, group)
			packages[key] = d
		}
	}

	if err := scanner.Err(); err != nil {
		return []models.PackageDetails{}, fmt.Errorf("ошибка в процессе парсинга %s: %w", depFile.Path, err)
	}

	return maps.Values(packages), nil
}

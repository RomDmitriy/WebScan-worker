package gitParser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
	"web-scan-worker/src/internal/cachedregexp"
	"web-scan-worker/src/internal/models"

	"golang.org/x/exp/maps"
)

const NpmEcosystem models.Ecosystem = "npm"

// Для пакетов, записанных в формате "npm:[name]@[version]"
type NpmLockDependency struct {
	Version      string                       `json:"version"`
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires map[string]string `json:"requires,omitempty"`
}

// Для пакетов из зависимостей
type NpmLockPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`

	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`

	Dev         bool `json:"dev,omitempty"`
	DevOptional bool `json:"devOptional,omitempty"`
	Optional    bool `json:"optional,omitempty"`

	Link bool `json:"link,omitempty"`
}

type NpmLockfile struct {
	Version int `json:"lockfileVersion"`
	// npm v1- lock-файлы используют "dependencies"
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`
	// npm v2+ lock-файлы используют "packages"
	Packages map[string]NpmLockPackage `json:"packages,omitempty"`
}

// Парсинг группы пакета для lock-файла <2
func (dep NpmLockDependency) depGroups() []string {
	if dep.Dev && dep.Optional {
		return []string{"dev", "optional"}
	}
	if dep.Dev {
		return []string{"dev"}
	}
	if dep.Optional {
		return []string{"optional"}
	}

	return nil
}

// Парсинг группы пакета для lock-файла 2+
func (pkg NpmLockPackage) depGroups() []string {
	if pkg.Dev {
		return []string{"dev"}
	}
	if pkg.Optional {
		return []string{"optional"}
	}
	if pkg.DevOptional {
		return []string{"dev", "optional"}
	}

	return nil
}

// Парсинг пакетов lock-файла для npm версии <2
func parseNpmLockDependencies(dependencies map[string]NpmLockDependency) map[string]models.PackageDetails {
	details := map[string]models.PackageDetails{}

	for name, detail := range dependencies {
		// Если у зависимости есть зависимости :)
		if detail.Dependencies != nil {
			// То рекурсивно проходимся по этим зависимостям
			maps.Copy(details, parseNpmLockDependencies(detail.Dependencies))
		}

		version := detail.Version
		finalVersion := version
		commit := ""

		// Если пакет имеет псевдоним, берём имя и версию
		if strings.HasPrefix(detail.Version, "npm:") {
			i := strings.LastIndex(detail.Version, "@")
			name = detail.Version[4:i]
			finalVersion = detail.Version[i+1:]
		}

		// Мы не можем получить версию из зависимости «file:»
		if strings.HasPrefix(detail.Version, "file:") {
			finalVersion = ""
		} else {
			commit = tryExtractCommit(detail.Version)

			// Если есть коммит, мы хотим выполнить анализ на основе него,
			// а не версии (версии в любом случае должны совпадать, чтобы коммиты совпадали).
			//
			// Также мы не можем узнать версию, поэтому просто ставим её пустой
			if commit != "" {
				finalVersion = ""
				version = commit
			}
		}

		// Собираем информацию о пакете в объект
		details[name+"@"+version] = models.PackageDetails{
			Name:      name,
			Version:   finalVersion,
			Ecosystem: NpmEcosystem,
			CompareAs: NpmEcosystem,
			Commit:    commit,
			DepGroups: detail.depGroups(),
		}
	}

	return details
}

// Парсинг названия библиотеки
func extractNpmPackageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

// Парсинг пакетов lock-файла для npm версии 2+
func parseNpmLockPackages(packages map[string]NpmLockPackage) map[string]models.PackageDetails {
	details := map[string]models.PackageDetails{}

	for namePath, detail := range packages {
		if namePath == "" {
			continue
		}

		// Пытаемся взять имя пакета
		finalName := detail.Name
		if finalName == "" {
			// Если безуспешно, то пробуем по другому
			finalName = extractNpmPackageName(namePath)
		}

		// Берём версию пакета
		finalVersion := detail.Version

		commit := tryExtractCommit(detail.Resolved)

		// если есть коммит, мы хотим выполнить анализ на основе него,
		// а не версии (версии в любом случае должны совпадать, чтобы коммиты совпадали)
		if commit != "" {
			finalVersion = commit
		}

		// Собираем информацию о пакете в объект
		details[finalName+"@"+finalVersion] = models.PackageDetails{
			Name:      finalName,
			Version:   detail.Version,
			Ecosystem: NpmEcosystem,
			CompareAs: NpmEcosystem,
			Commit:    commit,
			DepGroups: detail.depGroups(),
		}
	}

	return details
}

// Парсинг npm lock-файла
func parseNpmLock(lockfile NpmLockfile) map[string]models.PackageDetails {
	// Если lock-файл версии 2+
	if lockfile.Packages != nil {
		return parseNpmLockPackages(lockfile.Packages)
	}

	// Если lock-файл версии <2
	return parseNpmLockDependencies(lockfile.Dependencies)
}

// Пытаемся получить версию с коммита
func tryExtractCommit(resolution string) string {
	// language=GoRegExp
	matchers := []string{
		// ssh://...
		// git://...
		// git+ssh://...
		// git+https://...
		`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`,
		// https://....git/...
		`(?:^|.+@)https://.+\.git#(\w+)$`,
		`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`,
		`.+#commit[:=](\w+)$`,
		// github:...
		// gitlab:...
		// bitbucket:...
		`^(?:github|gitlab|bitbucket):.+#(\w+)$`,
	}

	for _, matcher := range matchers {
		re := cachedregexp.MustCompile(matcher)
		matched := re.FindStringSubmatch(resolution)

		if matched != nil {
			return matched[1]
		}
	}

	u, err := url.Parse(resolution)

	if err == nil {
		gitRepoHosts := []string{
			"bitbucket.org",
			"github.com",
			"gitlab.com",
		}

		for _, host := range gitRepoHosts {
			if u.Host != host {
				continue
			}

			if u.RawQuery != "" {
				queries := u.Query()

				if queries.Has("ref") {
					return queries.Get("ref")
				}
			}

			return u.Fragment
		}
	}

	return ""
}

type NpmLockExtractor struct{}

func extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockfile *NpmLockfile

	err := json.Unmarshal([]byte(f.Content), &parsedLockfile)

	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path, err)
	}

	return maps.Values(parseNpmLock(*parsedLockfile)), nil
}

func ParseNpmLock(depFile DepFile) ([]models.PackageDetails, error) {
	res, err := extract(depFile)

	if err != nil {
		return nil, err
	}

	return res, nil
}

package gitParser

import (
	"fmt"
	"sort"
	"web-scan-worker/internal/models"
)

type PackageDetailsParser = func(depFile DepFile) ([]models.PackageDetails, error)

func findParser(pathToLockfile DepFile) (PackageDetailsParser, string) {
	parseAs := pathToLockfile.Name

	return Parsers[parseAs], parseAs
}

// this is an optimisation and read-only
var Parsers = map[string]PackageDetailsParser{
	// "buildscript-gradle.lockfile": ParseGradleLock,
	// "Cargo.lock":                  ParseCargoLock,
	// "composer.lock":               ParseComposerLock,
	// "conan.lock":                  ParseConanLock,
	// "Gemfile.lock":                ParseGemfileLock,
	// "go.mod":                      ParseGoLock,
	// "gradle.lockfile":             ParseGradleLock,
	// "mix.lock":                    ParseMixLock,
	// "Pipfile.lock":                ParsePipenvLock,
	"package-lock.json": ParseNpmLock,
	// "packages.lock.json":          ParseNuGetLock,
	// "pdm.lock":                    ParsePdmLock,
	// "pnpm-lock.yaml":              ParsePnpmLock,
	// "poetry.lock":                 ParsePoetryLock,
	// "pom.xml":                     ParseMavenLock,
	// "pubspec.lock":                ParsePubspecLock,
	// "renv.lock":                   ParseRenvLock,
	// "requirements.txt":            ParseRequirementsTxt,
	// "yarn.lock":                   ParseYarnLock,
}

var lockfileExtractors = map[string]Extractor{}

type DepFile struct {
	Name    string
	Path    string
	Content string
}

type Extractor interface {
	// ShouldExtract checks if the Extractor should be used for the given path.
	ShouldExtract(path string) bool
	Extract(f DepFile) ([]models.PackageDetails, error)
}

func FindExtractor(path, extractAs string) (Extractor, string) {
	if extractAs != "" {
		return lockfileExtractors[extractAs], extractAs
	}

	for name, extractor := range lockfileExtractors {
		if extractor.ShouldExtract(path) {
			return extractor, name
		}
	}

	return nil, ""
}

// Парсинг lock-файла.
// На вход поступает путь до файла и как его парсить (можно оставить пустые кавычки для определения по имени файла)
// На выходе получаем библиотеки и их версии
func ExtractDeps(depFile DepFile) (models.Lockfile, error) {
	parser, extractedAs := findParser(depFile)

	if parser == nil {
		return models.Lockfile{}, fmt.Errorf("не найден парсер для lock-файла %s", depFile.Path)
	}

	packages, err := parser(depFile)

	// Если парсер вернул ошибку
	if err != nil {
		err = fmt.Errorf("ошибка при парсинге: %s", err)
	}

	// Избавляемся от повторений пакетов, беря самую большую версию.
	// Заодно сортируем пакеты по названию.
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return models.Lockfile{
		FilePath: depFile.Path,
		ParsedAs: extractedAs,
		Packages: packages,
	}, err
}

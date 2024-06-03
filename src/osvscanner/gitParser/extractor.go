package gitParser

import (
	"fmt"
	"sort"
	"web-scan-worker/src/osvscanner/models"
)

type PackageDetailsParser = func(depFile DepFile) ([]models.PackageDetails, error)

func findParser(pathToLockfile DepFile) (PackageDetailsParser, string) {
	parseAs := pathToLockfile.Name

	return Parsers[parseAs], parseAs
}

var Parsers = map[string]PackageDetailsParser{
	"package-lock.json": ParseNpmLock,
	"requirements.txt":  ParseRequirementsTxt,
}

type DepFile struct {
	Name    string
	Path    string
	Content string
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

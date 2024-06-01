package gitParser

import (
	"fmt"
	"slices"

	"github.com/google/go-github/v62/github"
	"golang.org/x/exp/maps"
)

type UserInfo struct {
	Token  string // Access token пользователя в сервисе git
	Id     int    // Id пользователя в БД
	User   string // Имя пользователя в сервисе git
	Repo   string // Наименование репозитория без указания владельца
	RepoId int    // Id репозитория в БД
}

type getContentsFunc func(path string, data UserInfo) (Directory, error)
type getDownload func(file github.RepositoryContent, data UserInfo) (github.RepositoryContent, error)

var gitGetContents = map[string]getContentsFunc{
	"github": GitHubGetContents,
}

var gitDownload = map[string]getDownload{
	"github": GitHubDownload,
}

var allowedFiles = maps.Keys(Parsers)

func getFunctions(service string) (getContentsFunc, getDownload, error) {
	var getContents = gitGetContents[service]
	var getDownload = gitDownload[service]
	if getContents == nil || getDownload == nil {
		return nil, nil, fmt.Errorf("unsupported service")
	}
	return getContents, getDownload, nil
}

// Рекурсивный обход директорий с возвратом путей до файлов
func recursiveParseDirs(path string, data UserInfo, getter getContentsFunc, downloader getDownload) ([]github.RepositoryContent, error) {
	// Получаем содержимое текущей папки
	dir, err := getter(path, data)
	if err != nil {
		return nil, err
	}

	// Создаём массив под файлы
	files := make([]github.RepositoryContent, 0)
	for _, iterFile := range dir.files {
		if slices.Contains(allowedFiles, *iterFile.Name) {
			// Для каждого файла вызываем ф-ию, чтобы получить содержимое этих файлов
			file, err := downloader(iterFile, data)
			if err != nil {
				return nil, err
			}
			files = append(files, file)
		}
	}

	// Рекурсивно изучаем папки дальше
	for _, dir := range dir.folders {
		childFolder, err := recursiveParseDirs(*dir.Path, data, getter, downloader)
		if err != nil {
			return nil, err
		}
		files = append(files, childFolder...)
	}

	// Возвращаем найденные файлы
	return files, nil
}

func GetFilesFromRepository(service string, user UserInfo) ([]github.RepositoryContent, error) {
	getContents, getDownload, err := getFunctions(service)
	if err != nil {
		return nil, err
	}

	files, err := recursiveParseDirs("/", user, getContents, getDownload)
	if err != nil {
		return nil, err
	}

	return files, nil
}

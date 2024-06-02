package gitParser

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v62/github"
)

type Directory struct {
	folders []github.RepositoryContent
	files   []github.RepositoryContent
}

func GitHubGetContents(path string, data UserInfo) (Directory, error) {
	if strings.Contains(path, "..") {
		fmt.Println("Получение содержимого из", path, "невозможно по причине запрета GitHub на содержание в пути \"..\"")
		return Directory{}, nil
	}
	fmt.Println("Пробуем получить содержимое из \"" + path + "\"")
	client := github.NewClient(nil).WithAuthToken(data.Token)

	_, dir, _, err := client.Repositories.GetContents(context.Background(), data.User, data.Repo, path, nil)

	if err != nil {
		return Directory{}, err
	}

	var files []github.RepositoryContent
	var folders []github.RepositoryContent

	for _, elem := range dir {
		if *elem.Type == "file" {
			files = append(files, *elem)
		}
		if *elem.Type == "dir" {
			folders = append(folders, *elem)
		}
	}

	// fmt.Println(files)

	return Directory{folders: folders, files: files}, nil
}

func GitHubDownload(file github.RepositoryContent, data UserInfo) (github.RepositoryContent, error) {
	fmt.Println("Пробуем скачать ", file.GetPath())
	client := github.NewClient(nil).WithAuthToken(data.Token)

	githubFile, _, _, err := client.Repositories.GetContents(context.Background(), data.User, data.Repo, file.GetPath(), nil)

	if err != nil {
		return github.RepositoryContent{}, err
	}

	return *githubFile, nil
}

package gitParser

import (
	"context"
	"fmt"

	"github.com/google/go-github/v62/github"
)

type Directory struct {
	folders []github.RepositoryContent
	files   []github.RepositoryContent
}

func GitHubGetContents(path string, data UserInfo) (Directory, error) {
	fmt.Println("Trying to get content from \"" + path + "\"")
	client := github.NewClient(nil).WithAuthToken(data.Token)

	_, dir, _, err := client.Repositories.GetContents(context.Background(), data.User, data.Repo, path, nil)

	if err != nil {
		return Directory{}, err
	}

	// req, _ := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", data.User, data.Repo, path), nil)
	// req.Header.Add("Authorization", "Bearer "+data.Token)
	// res, err := client.Do(req)

	// if err != nil {
	// 	return Directory{}, GitHubResponseFile{}, err
	// }

	// defer res.Body.Close()

	// body, _ := io.ReadAll(res.Body)

	// // Пытаемся распарсить весь ответ как файл
	// err = json.Unmarshal(body, &fileContent)
	// if err == nil {
	// 	// Если успешно, то возвращаем
	// 	return Directory{folders: nil, files: nil}, fileContent, nil
	// }

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
	fmt.Println("Trying to download", file.GetPath())
	client := github.NewClient(nil).WithAuthToken(data.Token)

	githubFile, _, _, err := client.Repositories.GetContents(context.Background(), data.User, data.Repo, file.GetPath(), nil)

	if err != nil {
		return github.RepositoryContent{}, err
	}

	// content, err := client.Client().Get(file.GetHTMLURL())

	// if err != nil {
	// 	return github.RepositoryContent{}, err
	// }

	// defer content.Body.Close()
	// body, _ := io.ReadAll(content.Body)
	// res := string(body)
	// // result := github.RepositoryContent{}
	// // err = json.Unmarshal(body, &result)
	// // if err != nil {
	// // 	return "", err
	// // }

	// githubFile.Content = &res

	return *githubFile, nil
}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"web-scan-worker/osvscanner"
	"web-scan-worker/osvscanner/gitParser"

	_ "web-scan-worker/docs"

	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger" // http-swagger middleware
)

// @Summary		Парсинг git-репозитория для получения уязвимостей в lock-файлах
// @Accept			json
// @Produce			json
// @Param			service			query		string						true	"Наименование сервиса" Enums(github, gitlab)
// @Param			user_info		body		gitParser.UserInfo			true	"Информация о пользователе и репозитории"
// @Success			200				object		models.VulnerabilityResults	"ok"
// @Failure			400
// @Failure			404
// @Failure			500
// @Router			/api/parse [post]
func parseRepo(w http.ResponseWriter, req *http.Request) {
	// file, _ := lockfile.OpenLocalDepFile()
	// var actions osvscanner.ScannerActions
	// actions.LockfilePaths = []string{"./tests/package-lock_v2/package-lock.json"}
	// actions.DirectoryPaths = []string{"./tests"}
	// actions.GitCommits = []string{"1bacc05ff50a7d26522c83039d69a27c50e65647"}

	// result, err := osvscanner.DoScan(actions)

	gitService := req.URL.Query().Get("service")

	if gitService != "github" && gitService != "gitlab" {
		fmt.Println("Unsupported git service")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var userData gitParser.UserInfo

	err := json.NewDecoder(req.Body).Decode(&userData)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	files, err := gitParser.GetFilesFromRepository(gitService, userData)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Println("\nResult list of lockfiles:")
	for _, file := range files {
		fmt.Println(file.GetPath())
	}
	fmt.Println("")

	response, err := osvscanner.DoScan(files, userData)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Println("\nSuccess!")

	// Тестовый вывод в файл
	b, _ := json.MarshalIndent(response, "", "  ")
	file, _ := os.Create("./output.json")
	file.Write(b)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// @title			WebScan Worker API
// @version			1.0
// @description		Этот сервис ищет lock-файлы в git-репозитории и возвращает список уязвимостей из базы данных osv.dev.

// @contact.name	Delevoper
// @contact.url		https://github.com/RomDmitriy

// @accept			json
// @produce			json
// @schemes			http

// @host			localhost:1323
// @BasePath  /

// @securityDefinitions.basic  BasicAuth
func main() {
	r := chi.NewRouter()

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:1323/swagger/doc.json"), //The url pointing to API definition
	))

	r.Post("/api/parse", parseRepo)

	fmt.Println("Worker started!")
	http.ListenAndServe(":1323", r)
}

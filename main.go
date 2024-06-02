package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"web-scan-worker/db"
	"web-scan-worker/src/database"
	"web-scan-worker/src/osvscanner"
	"web-scan-worker/src/osvscanner/gitParser"

	_ "web-scan-worker/docs"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	httpSwagger "github.com/swaggo/http-swagger" // http-swagger middleware
)

type severityCounts struct {
	Low      int
	Moderate int
	High     int
}

// @Summary			Парсинг git-репозитория для получения уязвимостей в lock-файлах
// @Accept			json
// @Produce			json
// @Param			service			query		string						true	"Наименование сервиса" Enums(github)
// @Param			user_info		body		gitParser.UserInfo			true	"Информация о пользователе и репозитории"
// @Success			200				object		severityCounts				"ok"
// @Failure			400
// @Failure			404
// @Failure			500
// @Router			/parse [post]
func parseRepo(w http.ResponseWriter, req *http.Request) {
	fmt.Println("==================================")

	// Получаем название сервиса
	gitService := req.URL.Query().Get("service")

	// Валидация допустимости сервиса
	if gitService != "github" {
		fmt.Println("Неподдерживаемый git-сервис")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Неподдерживаемый git-сервис"))
		return
	}

	// Парсим body запроса
	var userData gitParser.UserInfo
	err := json.NewDecoder(req.Body).Decode(&userData)
	if err != nil {
		fmt.Println("Ошибка при декодировании:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Println("Репозиторий:", userData.User+"/"+userData.Repo)

	client := database.PClient.Client
	ctx := context.Background()

	// Помечаем репозиторий, что он сканируется
	client.Repos.FindMany(
		db.Repos.ID.Equals(userData.RepoId),
	).Update(
		db.Repos.Status.Set(db.RepoStatusScanning),
	).Exec(ctx)

	// Получаем интересующие нас файлы
	files, err := gitParser.GetFilesFromRepository(gitService, userData)
	if err != nil {
		fmt.Println("Ошибка при парсинге файлов:", err)
		return
	}

	// scan
	scan, err := client.Scans.CreateOne(
		db.Scans.Repoitory.Link(db.Repos.ID.Equals(userData.RepoId)),
	).Exec(ctx)

	if err != nil {
		fmt.Println("Ошибка при создании Скана в ЬД:", err)
		return
	}

	var counts severityCounts

	if len(files) != 0 {
		// Логгирование
		fmt.Println()
		fmt.Println("Итоговый список lock-файлов:")
		for _, file := range files {
			fmt.Println("-", file.GetPath())
		}
		fmt.Println()

		// Сканируем файлы на наличие уязвимостей
		results, err := osvscanner.DoScan(files, userData)
		if err != nil {
			fmt.Println("Ошибка при поиске уязвимостей:", err)
			return
		}

		// Сохраняем информацию в БД
		fmt.Println()

		for _, source := range results.Results {
			fmt.Println("Источник", source.Source.Path)

			// sources
			src, err := client.Sources.CreateOne(
				db.Sources.Path.Set(source.Source.Path),
				db.Sources.Scan.Link(db.Scans.ID.Equals(scan.ID)),
			).Exec(ctx)

			if err != nil {
				fmt.Println("Ошибка при создании Источников:", err)
			}

			for _, pkg := range source.Packages {
				fmt.Println("- Пакет", pkg.Package.Name)
				// Packages
				_, err := client.Packages.UpsertOne(
					db.Packages.NameEcosystemVersion(
						db.Packages.Name.Equals(pkg.Package.Name),
						db.Packages.Ecosystem.Equals(db.Ecosystem(pkg.Package.Ecosystem)),
						db.Packages.Version.Equals(pkg.Package.Version),
					),
				).Create(
					db.Packages.Name.Set(pkg.Package.Name),
					db.Packages.Version.Set(pkg.Package.Version),
					db.Packages.Ecosystem.Set(db.Ecosystem(pkg.Package.Ecosystem)),
				).Update().Exec(ctx)

				if err != nil {
					fmt.Println("Ошибка при создании/обновлении пакетов:", err)
				}

				for _, severity := range pkg.Vulnerabilities {
					fmt.Println("--- Уязвимость", severity.ID)

					max_sev, _ := strconv.ParseFloat(pkg.Groups[0].MaxSeverity, 32)
					sev_category := db.SeverityType(osvscanner.ParseSeverityCategory(max_sev))
					switch sev_category {
					case db.SeverityTypeLow:
						{
							counts.Low += 1
							break
						}
					case db.SeverityTypeModerate:
						{
							counts.Moderate += 1
							break
						}
					case db.SeverityTypeHigh:
						{
							counts.High += 1
							break
						}
					}

					// Severities
					_, err := client.Severities.UpsertOne(
						db.Severities.ID.Equals(severity.ID),
					).Create(
						db.Severities.ID.Set(severity.ID),
						db.Severities.Modified.Set(severity.Modified),
						db.Severities.Published.Set(severity.Published),
						db.Severities.Summary.Set(severity.Summary),
						db.Severities.Details.Set(severity.Details),
						db.Severities.Severity.Set(sev_category),
						db.Severities.Packages.Link(
							db.Packages.NameEcosystemVersion(
								db.Packages.Name.Equals(pkg.Package.Name),
								db.Packages.Ecosystem.Equals(db.Ecosystem(pkg.Package.Ecosystem)),
								db.Packages.Version.Equals(pkg.Package.Version),
							),
						),
						db.Severities.Aliases.Set(severity.Aliases),
					).Update(
						db.Severities.Modified.Set(severity.Modified),
						db.Severities.Published.Set(severity.Published),
						db.Severities.Aliases.Set(severity.Aliases),
						db.Severities.Summary.Set(severity.Summary),
						db.Severities.Details.Set(severity.Details),
						db.Severities.Severity.Set(sev_category),
						db.Severities.Packages.Link(
							db.Packages.NameEcosystemVersion(
								db.Packages.Name.Equals(pkg.Package.Name),
								db.Packages.Ecosystem.Equals(db.Ecosystem(pkg.Package.Ecosystem)),
								db.Packages.Version.Equals(pkg.Package.Version),
							),
						),
					).Exec(ctx)

					if err != nil {
						fmt.Println("Ошибка при создании/обновлении уязвимости:", err)
					}
				}

				// PackagesInSources
				_, err = client.PackagesInSources.CreateOne(
					db.PackagesInSources.Packages.Link(
						db.Packages.NameEcosystemVersion(
							db.Packages.Name.Equals(pkg.Package.Name),
							db.Packages.Ecosystem.Equals(db.Ecosystem(pkg.Package.Ecosystem)),
							db.Packages.Version.Equals(pkg.Package.Version),
						),
					),
					db.PackagesInSources.Sources.Link(
						db.Sources.ID.Equals(src.ID),
					),
				).Exec(ctx)

				if err != nil {
					fmt.Println("Ошибка при создании связи Пакет-Источник:", err)
				}
			}
		}
	}

	// Помечаем репозиторий просканированным
	client.Repos.FindMany(
		db.Repos.ID.Equals(userData.RepoId),
	).Update(
		db.Repos.Status.Set(db.RepoStatusScanned),
	).Exec(ctx)

	_, err = client.Scans.FindMany(
		db.Scans.ID.Equals(
			scan.ID,
		),
	).Update(
		db.Scans.LowSeverity.Set(counts.Low),
		db.Scans.ModerateSeverity.Set(counts.Moderate),
		db.Scans.HighSeverity.Set(counts.High),
	).Exec(ctx)

	//TODO: кол-во пакетов в категориях не совпадает с кол-вом уязвимостей
	if err != nil {
		fmt.Println("Ошибка при попытке пометить репозиторий просканированным:", err)
	}

	fmt.Println()
	fmt.Println("Успех!")
	fmt.Println("==================================")

	// Возвращаем результат
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(counts)
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

func main() {
	godotenv.Load()

	// Подключение к БД
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Client.Disconnect()

	// Настройка API
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: []string{"https://*", "http://*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"POST"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:1323/swagger/doc.json"),
	))

	r.Post("/parse", parseRepo)

	fmt.Println("Процесс запущен!")
	http.ListenAndServe(":1323", r)
}

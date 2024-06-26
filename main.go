package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"web-scan-worker/db"
	"web-scan-worker/src/database"
	"web-scan-worker/src/osvscanner"
	"web-scan-worker/src/osvscanner/gitParser"
	"web-scan-worker/src/osvscanner/models"

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
	fmt.Println()

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

	// Создаём запись о сканировании
	scan, err := client.Scans.CreateOne(
		db.Scans.Repoitory.Link(db.Repos.ID.Equals(userData.RepoId)),
	).Exec(ctx)

	if err != nil {
		fmt.Println("Ошибка при создании Скана в БД:", err)
		return
	}

	var counts severityCounts
	counts.Low = 0
	counts.Moderate = 0
	counts.High = 0

	// Логгирование
	if len(files) > 0 {
		fmt.Println()
		fmt.Println("Итоговый список lock-файлов:")
		for _, file := range files {
			fmt.Println("-", file.GetPath())

		}
		fmt.Println()
	}

	// Сканируем файлы на наличие уязвимостей
	results, err := osvscanner.DoScan(files, userData)
	if err != nil {
		fmt.Println("Ошибка при поиске уязвимостей:", err)
		return
	}

	// Добавляем информацию об источниках, даже если в них нет уязвимых пакетов
	for _, source := range files {
		isExists := false
		for _, res := range results.Results {
			if res.Source.Path == source.GetPath() {
				isExists = true
			}
		}

		if !isExists {
			results.Results = append(results.Results, models.PackageSource{
				Source: models.SourceInfo{
					Path: source.GetPath(),
					Type: source.GetType(),
				},
				Packages: []models.PackageVulns{},
			})
		}
	}

	// Сохраняем информацию в БД
	fmt.Println()

	for _, source := range results.Results {
		fmt.Println("Источник", source.Source.Path)

		// Создаём запись об источнике
		src, err := client.Sources.CreateOne(
			db.Sources.Path.Set(source.Source.Path),
			db.Sources.Scan.Link(db.Scans.ID.Equals(scan.ID)),
		).Exec(ctx)

		if err != nil {
			fmt.Println("Ошибка при создании Источников:", err)
		}

		// Защита от дубликатов уязвимостей
		var prevVulnID string
		var prevVulnPackage string

		for _, pkg := range source.Packages {
			fmt.Println("- Пакет", pkg.Package.Name)
			// Создаём запись о пакете
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

			for _, Vulnerabilities := range pkg.Vulnerabilities {
				// Защита от дубликатов уязвимостей
				if prevVulnPackage == pkg.Package.Name && prevVulnID == Vulnerabilities.ID {
					continue
				}
				prevVulnPackage = pkg.Package.Name
				prevVulnID = Vulnerabilities.ID

				fmt.Println("--- Уязвимость", Vulnerabilities.ID)

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

				// Создаём запись о уязвимости
				vul, err := client.Vulnerabilities.UpsertOne(
					db.Vulnerabilities.ID.Equals(Vulnerabilities.ID),
				).Create(
					db.Vulnerabilities.ID.Set(Vulnerabilities.ID),
					db.Vulnerabilities.Modified.Set(Vulnerabilities.Modified),
					db.Vulnerabilities.Published.Set(Vulnerabilities.Published),
					db.Vulnerabilities.Summary.Set(Vulnerabilities.Summary),
					db.Vulnerabilities.Details.Set(Vulnerabilities.Details),
					db.Vulnerabilities.Severity.Set(sev_category),
					db.Vulnerabilities.Packages.Link(
						db.Packages.NameEcosystemVersion(
							db.Packages.Name.Equals(pkg.Package.Name),
							db.Packages.Ecosystem.Equals(db.Ecosystem(pkg.Package.Ecosystem)),
							db.Packages.Version.Equals(pkg.Package.Version),
						),
					),
					db.Vulnerabilities.Aliases.Set(Vulnerabilities.Aliases),
				).Update(
					db.Vulnerabilities.Modified.Set(Vulnerabilities.Modified),
					db.Vulnerabilities.Published.Set(Vulnerabilities.Published),
					db.Vulnerabilities.Aliases.Set(Vulnerabilities.Aliases),
					db.Vulnerabilities.Summary.Set(Vulnerabilities.Summary),
					db.Vulnerabilities.Details.Set(Vulnerabilities.Details),
					db.Vulnerabilities.Severity.Set(sev_category),
					db.Vulnerabilities.Packages.Link(
						db.Packages.NameEcosystemVersion(
							db.Packages.Name.Equals(pkg.Package.Name),
							db.Packages.Ecosystem.Equals(db.Ecosystem(pkg.Package.Ecosystem)),
							db.Packages.Version.Equals(pkg.Package.Version),
						),
					),
				).Exec(ctx)

				for _, reference := range Vulnerabilities.References {
					// Создаём запись о ссылке на сторонний источник
					_, err := client.References.UpsertOne(
						db.References.TypeURL(
							db.References.Type.Equals(db.ReferenceType(reference.Type)),
							db.References.URL.Equals(reference.URL),
						),
					).Create(
						db.References.Type.Set(db.ReferenceType(reference.Type)),
						db.References.URL.Set(reference.URL),
						db.References.Vulnerabilities.Link(db.Vulnerabilities.ID.Equals(vul.ID)),
					).Update(
						db.References.Type.Set(db.ReferenceType(reference.Type)),
						db.References.URL.Set(reference.URL),
						db.References.VulnerabilitiesID.Set(vul.ID),
					).Exec(ctx)

					if err != nil {
						fmt.Println("Ошибка при создании/обновлении Ссылок", err)
					}
				}

				if err != nil {
					fmt.Println("Ошибка при создании/обновлении Уязвимости:", err)
				}
			}

			// Создаём запись о связи пакета и источника
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
	// Подгружаем .env файл
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
		AllowedOrigins: []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Регистрируем роут до Swagger-документации
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:"+os.Getenv("PORT")+"/swagger/doc.json"),
	))

	// Регистрируем роут до функции сканирования репозитория на наличие уязвимостей
	r.Post("/parse", parseRepo)

	fmt.Println("Процесс запущен! Порт", os.Getenv("PORT"))
	http.ListenAndServe(":"+os.Getenv("PORT"), r)
}

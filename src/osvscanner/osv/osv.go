package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"
	"web-scan-worker/src/osvscanner/models"

	"golang.org/x/sync/semaphore"
)

const (
	// URL для отправки запросов к OSV
	QueryEndpoint = "https://api.osv.dev/v1/querybatch"
	// URL для получения списка уязвимостей в OSV
	GetEndpoint = "https://api.osv.dev/v1/vulns"
	// URL-адрес для публикации запросов определения версии в OSV
	DetermineVersionEndpoint = "https://api.osv.dev/v1experimental/determineversion"
	// Максимальное кол-во пакетов на запрос
	maxQueriesPerRequest = 1000
	// Максимальное кол-во запросов списка уязвимостей
	maxConcurrentRequests = 25
	// Максимальное число попыток отправки запроса
	maxRetryAttempts = 4
	// Множитель задержки между повторами запроса
	jitterMultiplier = 2
)

var RequestUserAgent = ""

// Пакет в OSV
type Package struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Запрос в OSV
type Query struct {
	Package  Package           `json:"package,omitempty"`
	Version  string            `json:"version,omitempty"`
	Source   models.SourceInfo `json:"-"`
	Metadata models.Metadata   `json:"-"`
}

// Пакетный запрос в OSV
type BatchedQuery struct {
	Queries []*Query `json:"queries"`
}

// Минимально наполненная уязвимость в OSV
type MinimalVulnerability struct {
	ID string `json:"id"`
}

// Минимальный ответ от OSV
type MinimalResponse struct {
	Vulns []MinimalVulnerability `json:"vulns"`
}

// Минимальный пакетный ответ от OSV
type BatchedResponse struct {
	Results []MinimalResponse `json:"results"`
}

// Полноценный ответ от OSV
type Response struct {
	Vulns []models.Vulnerability `json:"vulns"`
}

// Полноценный пакетный ответ от OSV
type HydratedBatchedResponse struct {
	Results []Response `json:"results"`
}

// Содержит хэш каждого файла и информацию о пути для определения версии
type DetermineVersionHash struct {
	Path string `json:"path"`
	Hash []byte `json:"hash"`
}

type DetermineVersionResponse struct {
	Matches []struct {
		Score    float64 `json:"score"`
		RepoInfo struct {
			Type    string `json:"type"`
			Address string `json:"address"`
			Tag     string `json:"tag"`
			Version string `json:"version"`
		} `json:"repo_info"`
	} `json:"matches"`
}

type determineVersionsRequest struct {
	Name       string                 `json:"name"`
	FileHashes []DetermineVersionHash `json:"file_hashes"`
}

func MakePkgRequest(pkgDetails models.PackageDetails) *Query {
	if pkgDetails.Ecosystem == "" {
		return &Query{
			Metadata: models.Metadata{
				RepoURL:   pkgDetails.Name,
				DepGroups: pkgDetails.DepGroups,
			},
		}
	} else {
		return &Query{
			Version: pkgDetails.Version,
			Package: Package{
				Name:      pkgDetails.Name,
				Ecosystem: string(pkgDetails.Ecosystem),
			},
			Metadata: models.Metadata{
				DepGroups: pkgDetails.DepGroups,
			},
		}
	}
}

func chunkBy[T any](items []T, chunkSize int) [][]T {
	chunks := make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}

	return append(chunks, items)
}

// checkResponseError проверяет ответ на ошибку
func checkResponseError(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ошибка при чтении ответа от сервера: %w", err)
	}
	defer resp.Body.Close()

	return fmt.Errorf("ошибка ответа сервера: %s", string(respBuf))
}

// Отправка пакетного запроса к OSV
func MakeRequest(request BatchedQuery) (*BatchedResponse, error) {
	client := http.DefaultClient

	// API имеет ограничение в кол-во пакетов на запрос
	queryChunks := chunkBy(request.Queries, maxQueriesPerRequest)
	var totalOsvResp BatchedResponse
	for _, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}

		resp, err := makeRetryRequest(func() (*http.Response, error) {
			requestBuf := bytes.NewBuffer(requestBytes)
			req, err := http.NewRequest(http.MethodPost, QueryEndpoint, requestBuf)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			if RequestUserAgent != "" {
				req.Header.Set("User-Agent", RequestUserAgent)
			}

			return client.Do(req)
		})
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var osvResp BatchedResponse
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&osvResp)
		if err != nil {
			return nil, err
		}

		totalOsvResp.Results = append(totalOsvResp.Results, osvResp.Results...)
	}

	return &totalOsvResp, nil

}

// Получаем уязвимость по ID
func GetWithClient(id string, client *http.Client) (*models.Vulnerability, error) {
	resp, err := makeRetryRequest(func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, GetEndpoint+"/"+id, nil)
		if err != nil {
			return nil, err
		}
		if RequestUserAgent != "" {
			req.Header.Set("User-Agent", RequestUserAgent)
		}

		return client.Do(req)
	})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var vuln models.Vulnerability
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// Заполняем результат
func Hydrate(resp *BatchedResponse) (*HydratedBatchedResponse, error) {
	return HydrateWithClient(resp, http.DefaultClient)
}

// Заполняем результат
func HydrateWithClient(resp *BatchedResponse, client *http.Client) (*HydratedBatchedResponse, error) {
	hydrated := HydratedBatchedResponse{}
	ctx := context.TODO()
	hydrated.Results = make([]Response, len(resp.Results))
	for idx := range hydrated.Results {
		hydrated.Results[idx].Vulns =
			make([]models.Vulnerability, len(resp.Results[idx].Vulns))
	}

	errChan := make(chan error)
	rateLimiter := semaphore.NewWeighted(maxConcurrentRequests)

	for batchIdx, response := range resp.Results {
		for resultIdx, vuln := range response.Vulns {
			if err := rateLimiter.Acquire(ctx, 1); err != nil {
				log.Panicf("не получилось получить семафор: %v", err)
			}

			go func(id string, batchIdx int, resultIdx int) {
				vuln, err := GetWithClient(id, client)
				if err != nil {
					errChan <- err
				} else {
					hydrated.Results[batchIdx].Vulns[resultIdx] = *vuln
				}

				rateLimiter.Release(1)
			}(vuln.ID, batchIdx, resultIdx)
		}
	}

	go func() {
		if err := rateLimiter.Acquire(ctx, maxConcurrentRequests); err != nil {
			log.Panicf("не получилось получить семафор: %v", err)
		}
		close(errChan)
	}()

	for err := range errChan {
		return nil, err
	}

	return &hydrated, nil
}

// Пробуем отправить запрос. Если тот не успешен, пробуем ещё несколько раз
func makeRetryRequest(action func() (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < maxRetryAttempts; i++ {
		jitterAmount := (rand.Float64() * float64(jitterMultiplier) * float64(i))
		time.Sleep(time.Duration(i*i)*time.Second + time.Duration(jitterAmount*1000)*time.Millisecond)

		resp, err = action()
		if err == nil {
			err = checkResponseError(resp)
			if err == nil {
				break
			}
		}
	}

	return resp, err
}

func MakeDetermineVersionRequest(name string, hashes []DetermineVersionHash) (*DetermineVersionResponse, error) {
	request := determineVersionsRequest{
		Name:       name,
		FileHashes: hashes,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := makeRetryRequest(func() (*http.Response, error) {
		requestBuf := bytes.NewBuffer(requestBytes)
		req, err := http.NewRequest(http.MethodPost, DetermineVersionEndpoint, requestBuf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if RequestUserAgent != "" {
			req.Header.Set("User-Agent", RequestUserAgent)
		}

		return http.DefaultClient.Do(req)
	})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result DetermineVersionResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

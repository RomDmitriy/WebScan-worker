package grouper

import (
	"slices"
	"sort"
	"web-scan-worker/src/osvscanner/models"

	"golang.org/x/exp/maps"
)

type IDAliases struct {
	ID      string
	Aliases []string
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func hasAliasIntersection(v1, v2 IDAliases) bool {
	// Проверка не пересекаются ли псевдонимы
	for _, alias := range v1.Aliases {
		if slices.Contains(v2.Aliases, alias) {
			return true
		}
	}
	// Проверка, находятся ли какие-либо идентификаторы в псевдонимах других
	return slices.Contains(v1.Aliases, v2.ID) || slices.Contains(v2.Aliases, v1.ID)
}

// Группируем уязвимости по псевдонимам
func Group(vulns []IDAliases) []models.GroupInfo {
	// Сопоставляем индекс `vulns` с идентификатором группы.
	// Идентификатор группы — это просто еще один индекс в срезе «vulns»
	groups := make([]int, len(vulns))

	// Изначально сделаем каждую уязвимость отдельной группой
	for i := 0; i < len(vulns); i++ {
		groups[i] = i
	}

	// Выполним попарное сравнение (n^2) и объединим все пересекающиеся уязвимости
	for i := 0; i < len(vulns); i++ {
		for j := i + 1; j < len(vulns); j++ {
			if hasAliasIntersection(vulns[i], vulns[j]) {
				// Объединяем две группы. Используем меньший индекс.
				groups[i] = min(groups[i], groups[j])
				groups[j] = groups[i]
			}
		}
	}

	// Развернём группу в конечную структуру
	extractedGroups := map[int][]string{}
	extractedAliases := map[int][]string{}
	for i, gid := range groups {
		extractedGroups[gid] = append(extractedGroups[gid], vulns[i].ID)
		extractedAliases[gid] = append(extractedAliases[gid], vulns[i].Aliases...)
	}

	// Сортируем по идентификатору группы для поддержания стабильного порядка тестов
	sortedKeys := maps.Keys(extractedGroups)
	sort.Ints(sortedKeys)

	result := make([]models.GroupInfo, 0, len(sortedKeys))
	for _, key := range sortedKeys {
		// Сортируем строки так, чтобы они всегда находились в одном и том же порядке
		sort.Strings(extractedGroups[key])

		// Добавляем IDs к псевдонимам
		extractedAliases[key] = append(extractedAliases[key], extractedGroups[key]...)

		// Убираем дубликаты
		sort.Strings(extractedAliases[key])
		extractedAliases[key] = slices.Compact(extractedAliases[key])

		result = append(result, models.GroupInfo{IDs: extractedGroups[key], Aliases: extractedAliases[key]})
	}

	return result
}

func ConvertVulnerabilityToIDAliases(c []models.Vulnerability) []IDAliases {
	output := []IDAliases{}
	for _, v := range c {
		idAliases := IDAliases{
			ID:      v.ID,
			Aliases: v.Aliases,
		}
		output = append(output, idAliases)
	}

	return output
}

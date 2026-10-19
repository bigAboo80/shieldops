package report

import (
	"fmt"
	"time"
)

// t translates a catalog key of language l; args fill its format verbs. A
// missing key comes back as is, which the tests catch.
func t(l, key string, args ...any) string {
	s, ok := catalog[l][key]
	if !ok {
		return key
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// plural returns the plural form of n: one, few or many (English has no few).
func plural(l string, n int) string {
	if l == "ru" {
		switch {
		case n%10 == 1 && n%100 != 11:
			return "one"
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return "few"
		}
		return "many"
	}
	if n == 1 {
		return "one"
	}
	return "many"
}

// sevLabel shows a severity; unknown ones as they are.
func sevLabel(l, s string) string {
	if _, ok := catalog[l]["sev."+s]; ok {
		return t(l, "sev."+s)
	}
	return s
}

// fmtTime shows a time in loc with the zone: 11.10.2026 18:30 МСК or
// 2026-10-11 18:30 MSK.
func fmtTime(l string, tm time.Time, loc *time.Location) string {
	if tm.IsZero() {
		return "—"
	}
	tm = tm.In(loc)
	zone := tm.Format("MST")
	if l == "ru" {
		if zone == "MSK" {
			zone = "МСК"
		}
		return tm.Format("02.01.2006 15:04") + " " + zone
	}
	return tm.Format("2006-01-02 15:04") + " " + zone
}

var catalog = map[string]map[string]string{
	"en": {
		"title":        "Kubernetes Cluster Security Report",
		"col.scan":     "Scan",
		"col.date":     "Date",
		"summary":      "Executive summary",
		"new":          "New since last scan",
		"resolved":     "Resolved since last scan",
		"assets":       "Assets",
		"edges":        "Relationships",
		"findings":     "Findings",
		"nofindings":   "No dangerous combinations were found in this scan.",
		"newbadge":     "New",
		"path":         "Attack path",
		"fix":          "How to fix",
		"fstek":        "FSTEK information protection measures",
		"fstek.source": "Source: %s.",
		"fstek.note":   "%d of %d measures violated.",
		"col.id":       "Measure",
		"col.desc":     "Requirement",
		"col.class":    "Class",
		"col.status":   "Status",
		"col.find":     "Findings",
		"col.rec":      "Recommendation",
		"st.fail":      "Violated",
		"st.ok":        "Met",
		"footer":       "Generated automatically by ShieldOps %s",
		"footer.dev":   "Generated automatically by ShieldOps",

		"sev.Critical": "Critical",
		"sev.High":     "High",
		"sev.Medium":   "Medium",
		"sev.Low":      "Low",
		"sev.":         "Other",

		"verdict.critical.one":  "%d critical finding needs immediate attention.",
		"verdict.critical.few":  "%d critical findings need immediate attention.",
		"verdict.critical.many": "%d critical findings need immediate attention.",
		"verdict.high.one":      "%d high-severity finding needs attention.",
		"verdict.high.few":      "%d high-severity findings need attention.",
		"verdict.high.many":     "%d high-severity findings need attention.",
		"verdict.other":         "Only medium- and low-severity findings: fix them as planned.",
		"verdict.none":          "No dangerous combinations were found.",
		"col.cluster":           "Cluster",
		"draft":                 "Draft: the mapping to FSTEK measures has not been confirmed by an expert.",
		"digest":                "SHA-256 of the scan data",
		"signkey":               "Signing key",
		"signnote":              "The report is signed: check it with shieldops verify and the .sig file next to it.",

		"platform":                  "Cluster platform",
		"platform.note":             "Components of Kubernetes and of the cluster's infrastructure. The provider of the cluster usually sets them up, or they need their privileges by design; they are not counted in the summary above.",
		"paths":                     "Attack paths",
		"paths.note":                "Ways from the Internet to Secrets, nodes and RBAC escalation, highest risk score (0–100) first.",
		"score":                     "Risk score",
		"path.internet":             "Internet",
		"edge.EXPOSES":              "exposes",
		"edge.ROUTES_TO":            "routes to",
		"edge.HAS_TOKEN":            "token of",
		"edge.MOUNTS_SECRET":        "mounts",
		"edge.ESCAPES_TO_NODE":      "escapes to",
		"edge.CAN_READ_SECRETS":     "can read",
		"edge.CAN_CREATE_WORKLOADS": "runs pods as",
		"edge.CAN_ESCALATE":         "escalates via",
		"edge.BOUND_TO_ROLE":        "bound to",
		"edge.CAN_REACH":            "reaches by network",
	},
	"ru": {
		"title":        "Отчёт о безопасности Kubernetes-кластера",
		"col.scan":     "Скан",
		"col.date":     "Дата",
		"summary":      "Резюме для руководства",
		"new":          "Новых с прошлого скана",
		"resolved":     "Устранено с прошлого скана",
		"assets":       "Активов",
		"edges":        "Связей",
		"findings":     "Находки",
		"nofindings":   "В этом скане опасных комбинаций не обнаружено.",
		"newbadge":     "Новая",
		"path":         "Цепочка атаки",
		"fix":          "Как исправить",
		"fstek":        "Меры защиты информации ФСТЭК России",
		"fstek.source": "Источник: %s.",
		"fstek.note":   "Нарушено мер: %d из %d.",
		"col.id":       "Мера",
		"col.desc":     "Требование",
		"col.class":    "Класс",
		"col.status":   "Статус",
		"col.find":     "Находки",
		"col.rec":      "Рекомендация",
		"st.fail":      "Нарушен",
		"st.ok":        "Выполнен",
		"footer":       "Сформировано автоматически, ShieldOps %s",
		"footer.dev":   "Сформировано автоматически, ShieldOps",

		"sev.Critical": "Критическая",
		"sev.High":     "Высокая",
		"sev.Medium":   "Средняя",
		"sev.Low":      "Низкая",
		"sev.":         "Прочие",

		"verdict.critical.one":  "%d критичная находка требует немедленного внимания.",
		"verdict.critical.few":  "%d критичные находки требуют немедленного внимания.",
		"verdict.critical.many": "%d критичных находок требуют немедленного внимания.",
		"verdict.high.one":      "%d находка высокой критичности требует внимания.",
		"verdict.high.few":      "%d находки высокой критичности требуют внимания.",
		"verdict.high.many":     "%d находок высокой критичности требуют внимания.",
		"verdict.other":         "Найдены только находки средней и низкой критичности — устраните их в плановом порядке.",
		"verdict.none":          "Опасных комбинаций не обнаружено.",
		"col.cluster":           "Кластер",
		"draft":                 "Черновик: сопоставление с мерами ФСТЭК не подтверждено экспертом.",
		"digest":                "SHA-256 данных скана",
		"signkey":               "Ключ подписи",
		"signnote":              "Отчёт подписан: проверьте его командой shieldops verify и файлом .sig рядом с ним.",

		"platform":                  "Платформа кластера",
		"platform.note":             "Компоненты Kubernetes и инфраструктуры кластера. Обычно их настраивает поставщик кластера или им нужны такие права по устройству; в сводке выше они не учитываются.",
		"paths":                     "Пути атаки",
		"paths.note":                "Цепочки из интернета до Secret, узлов и повышения прав в RBAC, по убыванию оценки риска (0–100).",
		"score":                     "Оценка риска",
		"path.internet":             "Интернет",
		"edge.EXPOSES":              "открывает",
		"edge.ROUTES_TO":            "направляет",
		"edge.HAS_TOKEN":            "токен",
		"edge.MOUNTS_SECRET":        "монтирует",
		"edge.ESCAPES_TO_NODE":      "выход на узел",
		"edge.CAN_READ_SECRETS":     "читает",
		"edge.CAN_CREATE_WORKLOADS": "запускает поды от имени",
		"edge.CAN_ESCALATE":         "повышает права через",
		"edge.BOUND_TO_ROLE":        "привязан к",
		"edge.CAN_REACH":            "достигает по сети",
	},
}

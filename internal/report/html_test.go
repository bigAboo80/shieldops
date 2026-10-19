package report

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bigAboo80/shieldops/internal/detectors"
)

func render(t *testing.T, d Data) string {
	t.Helper()
	var b strings.Builder
	if err := WriteHTML(&b, d); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func sample() Data {
	return Data{
		ScanID: 42, Generated: time.Date(2026, 10, 11, 15, 30, 0, 0, time.UTC), Assets: 120, Edges: 340, Version: "0.2", FSTEK: "117",
		Findings: []detectors.Finding{
			{Severity: "High", Title: "Exposed secret", Description: "Deployment/web", AttackPath: []string{"Internet", "Service/web", "Secret/db"},
				Remediation: "Use ClusterIP", FSTEKControls: []string{"УПД.3"}, FSTEK117: []string{"ЗКС.1"}, Recommendation: "Restrict access"},
			{Severity: "Critical", Title: "cluster-admin", Description: "SA ci", New: true, FSTEKControls: []string{"УПД.5"}, FSTEK117: []string{"ЗКО.3"}},
		},
		Delta: detectors.Delta{Baseline: true, New: 1, Resolved: []detectors.Finding{{Severity: "High", Title: "Gone", Description: "Deployment/old"}}},
	}
}

func TestWriteHTMLEscapesFindingText(t *testing.T) {
	t.Parallel()
	payload := `<script>alert(1)</script>`
	tests := []struct {
		name    string
		finding detectors.Finding
	}{
		{"title", detectors.Finding{Severity: "High", Title: payload}},
		{"description", detectors.Finding{Severity: "High", Description: payload}},
		{"attack path", detectors.Finding{Severity: "High", AttackPath: []string{"Internet", payload, `"><img src=x onerror=alert(1)>`}}},
		{"remediation", detectors.Finding{Severity: "High", Remediation: payload}},
		{"severity", detectors.Finding{Severity: payload}},
		{"recommendation", detectors.Finding{Severity: "High", Recommendation: payload,
			FSTEKControls: []string{"АНЗ.1"}, FSTEK117: []string{"ЗКО.8"}}},
	}
	for _, tt := range tests {
		for _, l := range Langs {
			t.Run(tt.name+" "+l, func(t *testing.T) {
				t.Parallel()
				d := Data{Lang: l, Findings: []detectors.Finding{tt.finding}}
				d.Resolved = []detectors.Finding{tt.finding}
				out := render(t, d)
				if strings.Contains(out, payload) || strings.Contains(out, "<img") {
					t.Errorf("report contains unescaped cluster data")
				}
			})
		}
	}
}

// rawKey matches a catalog key that leaked into the report untranslated.
var rawKey = regexp.MustCompile(`\b(col|st|sev|verdict|fstek|footer)\.[A-Za-z0-9_.]+`)

func TestRenderBothLanguages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		lang string
		want []string
	}{
		{"ru", []string{`<html lang="ru">`, "Отчёт о безопасности Kubernetes-кластера", "№42", "11.10.2026 18:30 МСК",
			"1 критичная находка требует немедленного внимания.", "Новая", "Цепочка атаки", "Устранено с прошлого скана", "Gone",
			"Нарушено мер: 2 из 9.", "Нарушен", "Выполнен", "Сформировано автоматически, ShieldOps 0.2"}},
		{"en", []string{`<html lang="en">`, "Kubernetes Cluster Security Report", "2026-10-11 18:30 MSK",
			"1 critical finding needs immediate attention.", ">New<", "Attack path", "Resolved since last scan",
			"2 of 9 measures violated.", "Violated", "Met", "Generated automatically by ShieldOps 0.2"}},
	}
	for _, tt := range tests {
		t.Run(tt.lang, func(t *testing.T) {
			t.Parallel()
			d := sample()
			d.Lang = tt.lang
			out := render(t, d)
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("report lacks %q", w)
				}
			}
			for _, bad := range []string{"<script", "http://", "https://", "%!", "<no value>", "shieldops.tech"} {
				if strings.Contains(out, bad) {
					t.Errorf("report contains %q", bad)
				}
			}
			body := out[strings.Index(out, "<body>"):]
			if m := rawKey.FindString(body); m != "" {
				t.Errorf("report shows the raw key %q", m)
			}
			// Critical findings come before high ones.
			if strings.Index(out, "cluster-admin") > strings.Index(out, "Exposed secret") {
				t.Error("findings are not grouped worst first")
			}
			for _, w := range []string{"Content-Security-Policy", "@media print", "size: A4", "break-inside: avoid", "prefers-color-scheme: light"} {
				if !strings.Contains(out, w) {
					t.Errorf("report lacks %q", w)
				}
			}
		})
	}
}

func TestDelta(t *testing.T) {
	t.Parallel()
	first := Data{Lang: "en", Findings: []detectors.Finding{{Severity: "High", Title: "T"}}}
	out := render(t, first)
	for _, s := range []string{">New<", "New since last scan", "Resolved since last scan"} {
		if strings.Contains(out, s) {
			t.Errorf("first scan shows %q", s)
		}
	}
	out = render(t, Data{Lang: "en", Findings: []detectors.Finding{{Severity: "High", Title: "T", New: true}},
		Delta: detectors.Delta{Baseline: true, New: 1, Resolved: []detectors.Finding{{Title: "Gone"}}}})
	for _, s := range []string{">New<", "New since last scan", "Resolved since last scan", "Gone"} {
		if !strings.Contains(out, s) {
			t.Errorf("report lacks %q", s)
		}
	}
}

func TestDefaultsAndTime(t *testing.T) {
	t.Parallel()
	ekb, err := time.LoadLocation("Asia/Yekaterinburg")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 22, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		d    Data
		want string
	}{
		{"defaults: ru, Moscow", Data{Generated: at}, "12.10.2026 01:00 МСК"},
		{"unknown lang falls back to ru", Data{Lang: "de", Generated: at}, `<html lang="ru">`},
		{"en, Moscow", Data{Lang: "en", Generated: at}, "2026-10-12 01:00 MSK"},
		{"ru, Yekaterinburg", Data{Lang: "ru", Generated: at, Location: ekb}, "12.10.2026 03:00 &#43;05"},
		{"en, UTC", Data{Lang: "en", Generated: at, Location: time.UTC}, "2026-10-11 22:00 UTC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if out := render(t, tt.d); !strings.Contains(out, tt.want) {
				t.Errorf("report lacks %q", tt.want)
			}
		})
	}
}

func TestVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		lang   string
		counts map[string]int
		want   string
	}{
		{"ru", map[string]int{"Critical": 2}, "2 критичные находки требуют немедленного внимания."},
		{"ru", map[string]int{"Critical": 5, "High": 1}, "5 критичных находок требуют немедленного внимания."},
		{"ru", map[string]int{"Critical": 21}, "21 критичная находка требует немедленного внимания."},
		{"ru", map[string]int{"High": 3}, "3 находки высокой критичности требуют внимания."},
		{"ru", map[string]int{"Low": 1}, "Найдены только находки средней и низкой критичности — устраните их в плановом порядке."},
		{"ru", map[string]int{}, "Опасных комбинаций не обнаружено."},
		{"en", map[string]int{"Critical": 2}, "2 critical findings need immediate attention."},
		{"en", map[string]int{"High": 1}, "1 high-severity finding needs attention."},
		{"en", map[string]int{}, "No dangerous combinations were found."},
	}
	for _, tt := range tests {
		total := 0
		for _, n := range tt.counts {
			total += n
		}
		if got := verdict(tt.lang, tt.counts, total); got != tt.want {
			t.Errorf("%s verdict(%v) = %q, want %q", tt.lang, tt.counts, got, tt.want)
		}
	}
}

func TestCatalogComplete(t *testing.T) {
	t.Parallel()
	for _, a := range Langs {
		for _, b := range Langs {
			for _, k := range slices.Sorted(maps.Keys(catalog[a])) {
				if catalog[b][k] == "" {
					t.Errorf("key %q of %s is missing or empty in %s", k, a, b)
				}
			}
		}
	}
	keys := []string{"sev."}
	for _, sev := range severities {
		keys = append(keys, "sev."+sev)
	}
	for _, form := range []string{"one", "few", "many"} {
		keys = append(keys, "verdict.critical."+form, "verdict.high."+form)
	}
	tmplKey := regexp.MustCompile(`\bt "([^"]+)"`)
	for _, m := range tmplKey.FindAllStringSubmatch(reportHTML, -1) {
		keys = append(keys, m[1])
	}
	for _, k := range keys {
		for _, l := range Langs {
			if _, ok := catalog[l][k]; !ok {
				t.Errorf("%s: key %q is used but missing", l, k)
			}
		}
	}
}

// TestDetectorTexts checks that findings are shown in the report's language
// and that their cluster data is escaped there.
func TestDetectorTexts(t *testing.T) {
	t.Parallel()
	hostPath := detectors.Finding{
		Detector: "host-path", Severity: "Critical", Title: "hostPath Volume",
		Description:    `p3/Deployment/x mounts node path /etc/<script>alert(1)</script>`,
		Remediation:    `Stop mounting /etc/<script>alert(1)</script> from the node`,
		Recommendation: "Replace hostPath with emptyDir, a PersistentVolume or a ConfigMap.",
		AttackPath:     []string{"p3/Deployment/x", "hostPath: /etc/<b>", "Node filesystem"},
		FSTEKControls:  []string{"УПД.3", "ОПС.1", "ЗИС.1"},
		FSTEK117:       []string{"ЗКО.5"},
	}
	tests := []struct {
		lang     string
		want     []string
		wantNone []string
	}{
		{"ru", []string{"Том hostPath", "монтирует путь узла /etc/&lt;script&gt;alert(1)&lt;/script&gt;", "Не монтируйте",
			"Замените hostPath на emptyDir", "Файловая система узла", "hostPath: /etc/&lt;b&gt;",
			"<td class=\"id\">ЗКО.5</td><td>Изоляция контейнеров в контейнерной среде</td>"},
			[]string{"hostPath Volume", "mounts node path", "<script>alert", "<b>"}},
		{"en", []string{"hostPath Volume", "mounts node path /etc/&lt;script&gt;", "Node filesystem",
			"<td class=\"id\">ЗКО.5</td><td>Isolation of containers in a container environment</td>"},
			[]string{"Том hostPath", "<script>alert"}},
	}
	for _, tt := range tests {
		t.Run(tt.lang, func(t *testing.T) {
			t.Parallel()
			out := render(t, Data{Lang: tt.lang, FSTEK: "117", Findings: []detectors.Finding{hostPath},
				Delta: detectors.Delta{Baseline: true, Resolved: []detectors.Finding{hostPath}}})
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("report lacks %q", w)
				}
			}
			for _, w := range tt.wantNone {
				if strings.Contains(out, w) {
					t.Errorf("report contains %q", w)
				}
			}
		})
	}
}

// TestOrders checks the measures table of each FSTEK order in both
// languages: its measures, the order named as the source, the violations.
func TestOrders(t *testing.T) {
	t.Parallel()
	f := detectors.Finding{Detector: "host-path", Severity: "Critical", Title: "hostPath Volume",
		FSTEKControls: []string{"УПД.3", "ОПС.1", "ЗИС.1"}, FSTEK117: []string{"ЗКО.5"}}
	tests := []struct {
		order, lang string
		want        []string
		wantNone    []string
	}{
		{"117", "ru", []string{"Источник: приказ ФСТЭК России от 11.04.2025 № 117", "от 12.04.2026", "Нарушено мер: 1 из 9.",
			`<td class="id">ЗКО.5</td>`, `<td class="id">МСЭ.1</td>`}, []string{`<td class="id">ЗИС.17</td>`, "№ 17 "}},
		{"117", "en", []string{"Source: FSTEK Order No. 117 of 11.04.2025", "1 of 9 measures violated.", `<td class="id">ЗКО.8</td>`},
			[]string{`<td class="id">ОПС.1</td>`}},
		{"17", "ru", []string{"Источник: приказ ФСТЭК России от 11.02.2013 № 17 (утратил силу с 01.03.2026", "Нарушено мер: 3 из 15.",
			`<td class="id">ЗИС.17</td>`, "Разбиение информационной системы на сегменты"}, []string{`<td class="id">ЗКО.5</td>`}},
		{"17", "en", []string{"Source: FSTEK Order No. 17 of 11.02.2013 (repealed", "3 of 15 measures violated."},
			[]string{`<td class="id">МСЭ.1</td>`}},
		{"", "ru", []string{"Том hostPath"}, []string{"Меры защиты информации ФСТЭК", "Нарушено мер", "Черновик"}}, // no -fstek: no table
		{"21", "en", []string{"No. 117", "1 of 9 measures violated."}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.order+" "+tt.lang, func(t *testing.T) {
			t.Parallel()
			out := render(t, Data{Lang: tt.lang, FSTEK: tt.order, Findings: []detectors.Finding{f}})
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("report lacks %q", w)
				}
			}
			for _, w := range tt.wantNone {
				if strings.Contains(out, w) {
					t.Errorf("report contains %q", w)
				}
			}
		})
	}
}

// TestControlsTable checks that each table lists every measure of its order.
func TestControlsTable(t *testing.T) {
	t.Parallel()
	for _, o := range detectors.Orders {
		rows := controls("ru", o.ID, nil)
		if len(rows) == 0 || len(rows) != len(detectors.ControlsOf(o.ID)) {
			t.Fatalf("order %s: table has %d measures, want %d", o.ID, len(rows), len(detectors.ControlsOf(o.ID)))
		}
		for _, r := range rows {
			if r.Name == "" || r.Classes == "" {
				t.Errorf("order %s: incomplete row %+v", o.ID, r)
			}
		}
	}
}

func TestDraftAndDigest(t *testing.T) {
	t.Parallel()
	d := sample()
	d.Cluster = "prod"
	digest := Digest(d)
	for _, tt := range []struct{ lang, draft, key string }{
		{"ru", "Черновик: сопоставление с мерами ФСТЭК не подтверждено экспертом.", "Ключ подписи"},
		{"en", "Draft: the mapping to FSTEK measures has not been confirmed by an expert.", "Signing key"},
	} {
		d.Lang, d.SignKey = tt.lang, ""
		out := render(t, d)
		if strings.Contains(out, tt.draft) == detectors.MappingReviewed {
			t.Errorf("%s: draft mark shown = %v with MappingReviewed = %v", tt.lang, !detectors.MappingReviewed, detectors.MappingReviewed)
		}
		if !strings.Contains(out, digest) || strings.Contains(out, tt.key) || !strings.Contains(out, "<dd>prod</dd>") {
			t.Errorf("%s: unsigned report: digest, key or cluster wrong", tt.lang)
		}
		d.SignKey = "SHA256:abc"
		if out := render(t, d); !strings.Contains(out, tt.key+": SHA256:abc") {
			t.Errorf("%s: signed report does not name its key", tt.lang)
		}
	}
	// The digest is of the data, not of the language or the key.
	d.SignKey = ""
	if Digest(d) != digest {
		t.Error("digest depends on the language")
	}
	d.Findings[0].Severity = "Low"
	if Digest(d) == digest {
		t.Error("digest does not change with the findings")
	}
}

// TestPlatformSection: findings of the cluster's platform are listed apart
// and do not count in the summary and the verdict.
func TestPlatformSection(t *testing.T) {
	t.Parallel()
	for _, lang := range []string{"ru", "en"} {
		d := sample()
		d.Lang = lang
		d.Findings = []detectors.Finding{
			{Severity: "Medium", Title: "App finding", Description: "shop/Deployment/api"},
			{Severity: "Critical", Title: "Platform finding", Description: "kube-system/DaemonSet/kube-proxy", Platform: true},
		}
		out := render(t, d)
		section := catalog[lang]["platform"]
		i := strings.Index(out, "<h2>"+section)
		if i < 0 {
			t.Fatalf("%s: no platform section", lang)
		}
		if strings.Index(out, "Platform finding") < i {
			t.Errorf("%s: platform finding outside its section", lang)
		}
		if !strings.Contains(out, "App finding") {
			t.Errorf("%s: application finding missing", lang)
		}
		if want := verdict(lang, map[string]int{"Medium": 1}, 1); !strings.Contains(out, want) {
			t.Errorf("%s: verdict counts platform findings, want %q", lang, want)
		}
	}
}

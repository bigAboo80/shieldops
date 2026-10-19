package detectors_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/bigAboo80/shieldops/internal/detectors"
	"github.com/bigAboo80/shieldops/internal/inventory"
)

// findingsOf runs every detector on the test clusters.
func findingsOf(t *testing.T) []detectors.Finding {
	t.Helper()
	ctx := context.Background()
	var all []detectors.Finding
	for _, snap := range []*inventory.Snapshot{scenario(), wildcardSnapshot()} {
		db := openDB(t)
		id := loadScan(t, ctx, db, snap)
		for _, d := range detectors.All {
			fs, err := d.Detect(ctx, db, id)
			if err != nil {
				t.Fatalf("%s: %v", d.ID, err)
			}
			all = append(all, fs...)
		}
	}
	return all
}

// TestFingerprintsStable pins fingerprints taken before texts moved to the
// catalog: triage keys decisions by them, so they must never change.
func TestFingerprintsStable(t *testing.T) {
	t.Parallel()
	want := []string{
		"cluster-admin-sa 2c42000c1fb1b3c16571a50a6896e5bc",
		"exposed-secret 41587a9b4d7a9e2dd6218992fa060b89",
		"exposed-cve 77ecbfa43e31c5e99f296924c419ef43",
		"no-network-policy 83ac770e202a78560d2979f6788b3f5f",
		"cluster-admin-sa 4a707c548816bfa86f814ad68917f01a",
		"privileged-container e51a5ff9b1a4b4e1cfb1015f21caed5b",
		"privileged-container 8ad5a9d67067a4daa795537a1ef6d46d",
		"host-namespaces 60e03027502f782bc454576a78d56dee",
		"host-path 36a0d24069607d3fe3d5bd6f1422e722",
		"host-path c292b45ebad7e6b47df2ae3d5e2e3e2d",
		"host-path a5fa6ced771ea56249a928dc2857cee0",
		"no-network-policy c17e7977ee3d4aaaacbe5522ac1014b2",
		"latest-tag c9f2bca096e5fe0ee8ad7488f5669b1c",
		"wildcard-rbac 7c4c7b2393e4f3422c8b2a156a7ada32",
		"wildcard-rbac fbcb9a5c3f4a63ecc6bafb4b8485d64c",
	}
	var got []string
	for _, f := range findingsOf(t) {
		if f.Detector != "attack-path" { // newer, pinned in TestAttackPathFingerprints
			got = append(got, f.Detector+" "+f.Fingerprint)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("fingerprints changed:\n got %q\nwant %q", got, want)
	}
}

// TestNamespaceSet checks that every finding names the namespace of its
// workload: triage keeps findings of excluded namespaces open by it.
func TestNamespaceSet(t *testing.T) {
	t.Parallel()
	for _, f := range findingsOf(t) {
		if f.Namespace == "" || !strings.Contains(f.Description, f.Namespace) {
			t.Errorf("%s: namespace %q, description %q", f.Detector, f.Namespace, f.Description)
		}
	}
}

func TestControlsKnown(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, c := range detectors.Controls {
		key := c.Order + " " + c.ID
		if _, ok := detectors.OrderByID(c.Order); !ok || seen[key] || c.NameRU == "" || c.NameEN == "" || c.Classes == "" {
			t.Errorf("control %+v has an unknown order, is duplicate or incomplete", c)
		}
		seen[key] = true
	}
	findings := findingsOf(t)
	for _, o := range detectors.Orders {
		used := map[string]bool{}
		for _, f := range findings {
			ids := f.ControlIDs(o.ID)
			if len(ids) == 0 {
				t.Errorf("order %s: %s maps to no measure", o.ID, f.Detector)
			}
			for _, id := range ids {
				used[id] = true
				if _, ok := detectors.ControlByID(o.ID, id); !ok {
					t.Errorf("order %s: %s refers to unknown measure %q", o.ID, f.Detector, id)
				}
			}
		}
		// A listed measure nothing checks would show as met in the report.
		if o.ID == "117" {
			for _, c := range detectors.ControlsOf(o.ID) {
				if !used[c.ID] {
					t.Errorf("order 117: measure %s is listed but no detector checks it", c.ID)
				}
			}
		}
	}
	if o := detectors.Orders[0]; o.ID != "117" {
		t.Errorf("default order = %s, want 117: it replaced order 17 on 01.03.2026", o.ID)
	}
}

// TestLocalize checks that every detector, with the values of the test
// clusters, has a complete Russian text and that English stays as produced.
func TestLocalize(t *testing.T) {
	t.Parallel()
	covered := map[string]bool{}
	for _, f := range findingsOf(t) {
		covered[f.Detector] = true
		if got := f.In("en"); !slices.Equal(got.AttackPath, f.AttackPath) || got.Description != f.Description {
			t.Errorf("%s: English changed: %+v", f.Detector, got)
		}
		ru := f.In("ru")
		for name, pair := range map[string][2]string{
			"title": {f.Title, ru.Title}, "description": {f.Description, ru.Description},
			"remediation": {f.Remediation, ru.Remediation}, "recommendation": {f.Recommendation, ru.Recommendation},
		} {
			if pair[1] == pair[0] || pair[1] == "" || strings.Contains(pair[1], "%!") || strings.Contains(pair[1], f.Detector+".") {
				t.Errorf("%s %s not translated: %q", f.Detector, name, pair[1])
			}
		}
		if len(ru.AttackPath) != len(f.AttackPath) {
			t.Errorf("%s: attack path %q became %q", f.Detector, f.AttackPath, ru.AttackPath)
		}
		for _, step := range ru.AttackPath {
			for _, word := range []string{"Internet", "Node", "Privileged container", "Any pod", "Unrestricted", "Registry", "Mutable tag", "Host namespace", "CVEs"} {
				if strings.Contains(step, word) {
					t.Errorf("%s: step %q not translated", f.Detector, step)
				}
			}
		}
		if fp := ru.Fingerprint; fp != f.Fingerprint || ru.Severity != f.Severity {
			t.Errorf("%s: translation changed fingerprint or severity", f.Detector)
		}
	}
	for _, d := range detectors.All {
		if !covered[d.ID] {
			t.Errorf("detector %s has no finding in the test clusters", d.ID)
		}
	}
}

func TestLocalizeData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, detector string
		in             detectors.Texts
		want           detectors.Texts
	}{
		{"cluster values are kept as they are", "host-path",
			detectors.Texts{Description: "ns/Pod/x mounts node path /var/<script>", Remediation: "Stop mounting /a b/c from the node"},
			detectors.Texts{Description: "ns/Pod/x монтирует путь узла /var/<script>", Remediation: "Не монтируйте /a b/c с узла"}},
		{"numbers", "no-network-policy",
			detectors.Texts{Description: "Namespace a: 3 workloads (5 pods) are not selected by any NetworkPolicy"},
			detectors.Texts{Description: "Namespace a: рабочих нагрузок без NetworkPolicy — 3 (подов — 5)"}},
		{"fixed versions", "exposed-cve",
			detectors.Texts{Description: "app/Deployment/web has 2 CVEs, top: [CVE-1(CRITICAL)]; fixed in openssl 3.0.15"},
			detectors.Texts{Description: "app/Deployment/web: уязвимостей CVE — 2, наиболее опасные: [CVE-1(CRITICAL)]; исправлено в openssl 3.0.15"}},
		{"no fixed versions", "exposed-cve",
			detectors.Texts{Description: "app/Deployment/web has 2 CVEs, top: [CVE-1(CRITICAL)]"},
			detectors.Texts{Description: "app/Deployment/web: уязвимостей CVE — 2, наиболее опасные: [CVE-1(CRITICAL)]"}},
		{"older text stays as it is", "host-path",
			detectors.Texts{Title: "Old Title", Description: "something else"},
			detectors.Texts{Title: "Old Title", Description: "something else"}},
		{"unknown detector", "removed",
			detectors.Texts{Title: "Privileged Container"},
			detectors.Texts{Title: "Privileged Container"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := detectors.Localize("ru", tt.detector, tt.in)
			if got.Title != tt.want.Title || got.Description != tt.want.Description || got.Remediation != tt.want.Remediation {
				t.Errorf("Localize = %+v, want %+v", got, tt.want)
			}
		})
	}
	if got := detectors.Localize("de", "host-path", detectors.Texts{Title: "hostPath Volume"}); got.Title != "hostPath Volume" {
		t.Errorf("unknown language changed the text: %q", got.Title)
	}
}

// TestDetectorControls checks that the measures of a detector are the ones
// its findings carry, for every order.
func TestDetectorControls(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, f := range findingsOf(t) {
		seen[f.Detector] = true
		for _, o := range detectors.Orders {
			got, want := detectors.DetectorControls(f.Detector, o.ID), f.ControlIDs(o.ID)
			// A path violates the measures of its steps, a part of the detector's.
			if f.Detector == "attack-path" && len(want) > 0 && !slices.ContainsFunc(want, func(id string) bool { return !slices.Contains(got, id) }) {
				continue
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s order %s: DetectorControls = %q, findings carry %q", f.Detector, o.ID, got, want)
			}
		}
	}
	for _, d := range detectors.All {
		if !seen[d.ID] {
			t.Errorf("%s: no finding on the test clusters, its measures are unchecked", d.ID)
		}
	}
	if got := detectors.DetectorControls("unknown", "117"); got != nil {
		t.Errorf("unknown detector: %q", got)
	}
}

// TestPlain checks that every detector explains itself in plain words in
// every language.
func TestPlain(t *testing.T) {
	t.Parallel()
	for _, lang := range []string{"en", "ru"} {
		for _, d := range detectors.All {
			t.Run(lang+"/"+d.ID, func(t *testing.T) {
				t.Parallel()
				why, do := detectors.Plain(lang, d.ID)
				if why == "" || do == "" {
					t.Fatalf("why = %q, do = %q", why, do)
				}
				if strings.Contains(why, "%") || strings.Contains(do, "%") {
					t.Errorf("format verbs in plain texts: %q, %q", why, do)
				}
				if enWhy, _ := detectors.Plain("en", d.ID); lang != "en" && why == enWhy {
					t.Errorf("not translated: %q", why)
				}
			})
		}
	}
	if why, _ := detectors.Plain("de", "latest-tag"); why == "" {
		t.Error("unknown language must fall back to English")
	}
}

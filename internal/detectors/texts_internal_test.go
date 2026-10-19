package detectors

import (
	"strings"
	"testing"
)

func TestCatalogComplete(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"en", "ru"} {
		for _, b := range []string{"en", "ru"} {
			for k := range texts[a] {
				if texts[b][k] == "" {
					t.Errorf("key %q of %s is missing or empty in %s", k, a, b)
				}
			}
		}
	}
	for _, d := range All {
		for _, field := range []string{"title", "desc", "fix", "rec"} {
			if texts["en"][d.ID+"."+field] == "" {
				t.Errorf("detector %s has no %s", d.ID, field)
			}
		}
	}
	// Every language takes the same values: format with sample values of
	// the verbs of the English text.
	for key, p := range parsers {
		args := make([]any, len(p.verbs))
		for i, v := range p.verbs {
			args[i] = "VALUE"
			if v == 'd' {
				args[i] = 7
			}
		}
		for _, l := range []string{"en", "ru"} {
			out := fmtText(l, key, args...)
			if strings.Contains(out, "%!") {
				t.Errorf("%s %s: %q", l, key, out)
			}
			if want := strings.Count(texts["en"][key], "%"); strings.Count(out, "VALUE")+strings.Count(out, "7") < want {
				t.Errorf("%s %s drops values: %q", l, key, out)
			}
		}
	}
}

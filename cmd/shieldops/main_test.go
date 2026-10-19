package main

import (
	"flag"
	"slices"
	"testing"
)

func TestReportLocale(t *testing.T) {
	t.Parallel()
	tests := []struct {
		lang, timezone, want string
		ok                   bool
	}{
		{"ru", "Europe/Moscow", "Europe/Moscow", true},
		{"en", "UTC", "UTC", true},
		{"en", "Asia/Yekaterinburg", "Asia/Yekaterinburg", true},
		{"de", "Europe/Moscow", "", false},
		{"", "Europe/Moscow", "", false},
		{"ru", "Europe/Atlantis", "", false},
		{"ru", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.lang+" "+tt.timezone, func(t *testing.T) {
			t.Parallel()
			loc, err := reportLocale(tt.lang, tt.timezone)
			if (err == nil) != tt.ok {
				t.Fatalf("reportLocale error = %v, want ok=%v", err, tt.ok)
			}
			if tt.ok && loc.String() != tt.want {
				t.Fatalf("location = %s, want %s", loc, tt.want)
			}
		})
	}
}

func TestExcludeNamespacesFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"default is empty", nil, nil},
		{"list with blanks", []string{"-exclude-namespaces=kube-system, kube-flannel,,local-path-storage"}, []string{"kube-system", "kube-flannel", "local-path-storage"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var cfg scanConfig
			cfg.register(fs)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			if got := csvList(cfg.excludeNamespaces); !slices.Equal(got, tt.want) {
				t.Errorf("csvList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckFSTEK(t *testing.T) {
	t.Parallel()
	tests := []struct {
		order      string
		allowEmpty bool
		ok         bool
	}{
		{"117", false, true}, {"17", false, true}, {"", false, false}, {"21", false, false}, {"117 ", false, false},
		{"", true, true}, {"21", true, false},
	}
	for _, tt := range tests {
		if err := checkFSTEK(tt.order, tt.allowEmpty); (err == nil) != tt.ok {
			t.Errorf("checkFSTEK(%q, %v) = %v, want ok=%v", tt.order, tt.allowEmpty, err, tt.ok)
		}
	}
}

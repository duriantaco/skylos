package analyzer

import "testing"

func TestCookieFlagsReportOnlyAbsentOrLiteralFalse(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"secure from parameter":      {"func set(w http.ResponseWriter, secure bool) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: secure, HttpOnly: true}) }\n", 0},
		"secure from config field":   {"type opts struct{ TLS bool }\n\nfunc set(w http.ResponseWriter, o opts) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: o.TLS, HttpOnly: true}) }\n", 0},
		"secure from request scheme": {"func set(w http.ResponseWriter, r *http.Request) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: r.TLS != nil, HttpOnly: true}) }\n", 0},
		"both literal true":          {"func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: true, HttpOnly: true}) }\n", 0},
		"secure absent":              {"func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", HttpOnly: true}) }\n", 1},
		"secure literal false":       {"func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: false, HttpOnly: true}) }\n", 1},
		"httponly literal false":     {"func set(w http.ResponseWriter, secure bool) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: secure, HttpOnly: false}) }\n", 1},
		"httponly absent":            {"func set(w http.ResponseWriter, secure bool) { http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: \"v\", Secure: secure}) }\n", 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := findingsByRule(t, tc.body)["SKY-G221"]
			if len(got) != tc.want {
				t.Fatalf("want %d SKY-G221, got %v", tc.want, got)
			}
		})
	}
}

func TestHandleStoredInCompositeLiteralIsNotUnclosed(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"unkeyed literal assigned to outer variable": {"type source struct {\n\tfile *os.File\n\tname string\n}\n\nvar current *source\n\nfunc run(p string) { f, _ := os.Open(p); current = &source{f, p} }\n", 0},
		"keyed literal appended to a slice":          {"type source struct {\n\tfile *os.File\n\tname string\n}\n\nvar all []source\n\nfunc run(p string) { f, _ := os.Open(p); all = append(all, source{file: f, name: p}) }\n", 0},
		"closure stores the handle":                  {"type source struct{ file *os.File }\n\nfunc run(ps []string) *source {\n\tvar found *source\n\tvisit := func(p string) {\n\t\tf, err := os.Open(p)\n\t\tif err != nil {\n\t\t\treturn\n\t\t}\n\t\tfound = &source{f}\n\t}\n\tfor _, p := range ps {\n\t\tvisit(p)\n\t}\n\treturn found\n}\n", 0},
		"literal holds only the name":                {"type entry struct{ name string }\n\nvar seen []entry\n\nfunc run(p string) { f, _ := os.Open(p); seen = append(seen, entry{name: f.Name()}) }\n", 1},
		"literal holds only the descriptor number":   {"type entry struct{ fd uintptr }\n\nvar seen []entry\n\nfunc run(p string) { f, _ := os.Open(p); seen = append(seen, entry{f.Fd()}) }\n", 1},
		"read and dropped":                           {"func run(p string) { f, _ := os.Open(p); buf := make([]byte, 1); f.Read(buf) }\n", 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := findingsByRule(t, tc.body)["SKY-G260"]
			if len(got) != tc.want {
				t.Fatalf("want %d SKY-G260, got %v", tc.want, got)
			}
		})
	}
}

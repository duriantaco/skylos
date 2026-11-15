package analyzer

import "testing"

func TestCookieFalseConstantsRemainInsecure(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"negated true": {`func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:!true, HttpOnly:true}) }`, 1},
		"constant alias": {`const insecure = false
func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:insecure, HttpOnly:true}) }`, 1},
		"local constant alias": {`func set(w http.ResponseWriter) { const insecure = false; http.SetCookie(w, &http.Cookie{Name:"sid", Secure:insecure, HttpOnly:true}) }`, 1},
		"false conjunction":    {`func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:true && false, HttpOnly:true}) }`, 1},
		"false equality":       {`func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:true == false, HttpOnly:true}) }`, 1},
		"false httponly":       {`func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:true, HttpOnly:!true}) }`, 1},
		"true constant": {`const secure = true
func set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:secure, HttpOnly:true}) }`, 0},
		"unknown parameter": {`func set(w http.ResponseWriter, secure bool) { http.SetCookie(w, &http.Cookie{Name:"sid", Secure:secure, HttpOnly:true}) }`, 0},
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

func TestCompositeHandleNeedsAnEscapingOwner(t *testing.T) {
	const prelude = `type source struct{ file *os.File }
`
	cases := map[string]struct {
		body string
		want int
	}{
		"discarded literal":          {`func leak(p string) { f, _ := os.Open(p); _ = source{file:f} }`, 1},
		"local owner discarded":      {`func leak(p string) { f, _ := os.Open(p); s := source{file:f}; _ = s }`, 1},
		"local collection discarded": {`func leak(p string) { f, _ := os.Open(p); all := []source{{file:f}}; _ = all }`, 1},
		"returned owner":             {`func keep(p string) source { f, _ := os.Open(p); s := source{file:f}; return s }`, 0},
		"closed owner":               {`func keep(p string) { f, _ := os.Open(p); s := source{file:f}; defer s.file.Close() }`, 0},
		"returned collection":        {`func keep(p string) []source { f, _ := os.Open(p); all := []source{{file:f}}; return all }`, 0},
		"global owner": {`var current source
func keep(p string) { f, _ := os.Open(p); s := source{file:f}; current = s }`, 0},
		"close only one field": {`type pair struct{ first, second *os.File }
func keep(p string) { f,_:=os.Open(p); g,_:=os.Open(p); s:=pair{first:f,second:g}; defer s.first.Close() }`, 1},
		"overwritten member":                         {`func leak(p string) { f,_:=os.Open(p); s:=source{file:f}; s.file=nil; s.file.Close() }`, 1},
		"overwritten aggregate":                      {`func leak(p string) { f,_:=os.Open(p); s:=source{file:f}; s=source{}; s.file.Close() }`, 1},
		"overwritten member returned":                {`func leak(p string) source { f,_:=os.Open(p); s:=source{file:f}; s.file=nil; return s }`, 1},
		"copied owner close":                         {`func keep(p string) { f,_:=os.Open(p); s:=source{file:f}; copied:=s; copied.file.Close() }`, 0},
		"unkeyed owner close":                        {`func keep(p string) { f,_:=os.Open(p); s:=source{f}; s.file.Close() }`, 0},
		"returned dereference":                       {`func keep(p string) source { f,_:=os.Open(p); s:=&source{file:f}; return *s }`, 0},
		"shadow does not erase returned owner":       {`func keep(p string) source { f,_:=os.Open(p); s:=source{file:f}; { s:=source{}; _=s }; return s }`, 0},
		"shadow does not invent escape":              {`func leak(p string) source { f,_:=os.Open(p); s:=source{}; { s:=source{file:f}; _=s }; return s }`, 1},
		"pointer alias member overwritten":           {`func leak(p string) *source { f,_:=os.Open(p); s:=&source{file:f}; alias:=s; alias.file=nil; return s }`, 1},
		"value copy member overwrite keeps original": {`func keep(p string) source { f,_:=os.Open(p); s:=source{file:f}; copied:=s; copied.file=nil; return s }`, 0},
		"addressed value member overwritten":         {`func leak(p string) source { f,_:=os.Open(p); s:=source{file:f}; ptr:=&s; ptr.file=nil; return s }`, 1},
		"addressed value copy stays independent":     {`func keep(p string) source { f,_:=os.Open(p); s:=source{file:f}; ptr:=&s; copied:=s; copied.file=nil; _=ptr; return s }`, 0},
		"addressed value replaced through storage":   {`func leak(p string) *source { f,_:=os.Open(p); s:=source{file:f}; ptr:=&s; s=source{}; return ptr }`, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := findingsByRule(t, prelude+tc.body)["SKY-G260"]
			if len(got) != tc.want {
				t.Fatalf("want %d SKY-G260, got %v", tc.want, got)
			}
		})
	}
}

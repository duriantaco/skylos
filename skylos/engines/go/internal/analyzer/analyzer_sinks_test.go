package analyzer

import (
	"testing"
)

const sinksPrelude = `package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"example.com/app/internal/sqlx"
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	realsqlx "github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

type Repo struct {
	db   *sql.DB
	pool *pgxpool.Pool
	sx   *realsqlx.DB
}

type Handler struct {
	repo   *Repo
	client *http.Client
}

type listQuery struct {
	Sort  string
	Limit int
}

var gdb *gorm.DB
var client = &http.Client{}
var page = template.Must(template.New("p").Parse("{{.}}"))

`

type sinkCase struct {
	body string
	rule string
	want []string
}

func runSinkCases(t *testing.T, cases map[string]sinkCase) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := severitiesFor(t, map[string]string{"app.go": sinksPrelude + tc.body}, tc.rule)
			assertSeverities(t, got, tc.want)
		})
	}
}

func TestSQLSinksFollowDatabaseLibraries(t *testing.T) {
	critical := []string{"CRITICAL"}
	runSinkCases(t, map[string]sinkCase{
		"struct field database/sql":           {"func (h *Handler) H(w http.ResponseWriter, r *http.Request) {\n\th.repo.db.QueryContext(r.Context(), \"SELECT * FROM t WHERE n = '\"+r.FormValue(\"n\")+\"'\")\n}\n", "SKY-G211", critical},
		"pgxpool checks the SQL, not ctx":     {"func (h *Handler) H(c *fiber.Ctx) error {\n\th.repo.pool.Query(context.Background(), \"SELECT * FROM t WHERE n = '\"+c.Query(\"n\")+\"'\")\n\treturn nil\n}\n", "SKY-G211", critical},
		"sqlx Select after the destination":   {"func (h *Handler) H(c *gin.Context) {\n\tvar out []string\n\th.repo.sx.Select(&out, \"SELECT n FROM t ORDER BY \"+c.Query(\"o\"))\n}\n", "SKY-G211", critical},
		"gorm Where concatenation":            {"func H(c *gin.Context) { gdb.Where(\"name = '\" + c.Query(\"n\") + \"'\").Find(nil) }\n", "SKY-G211", critical},
		"gorm Order from the request":         {"func H(c *gin.Context) { gdb.Order(c.Query(\"sort\")).Find(nil) }\n", "SKY-G211", critical},
		"gorm bound string field":             {"func H(c *gin.Context) {\n\tvar q listQuery\n\tc.ShouldBindQuery(&q)\n\tgdb.Order(q.Sort).Find(nil)\n}\n", "SKY-G211", critical},
		"gorm inline string condition":        {"func H(c *gin.Context) {\n\tvar u struct{ ID int }\n\tgdb.First(&u, c.Param(\"id\"))\n}\n", "SKY-G211", critical},
		"atoi error ignored, raw string used": {"func H(w http.ResponseWriter, r *http.Request) {\n\traw := r.FormValue(\"id\")\n\t_, _ = strconv.Atoi(raw)\n\tgdb.Exec(fmt.Sprintf(\"DELETE FROM t WHERE id = %s\", raw))\n}\n", "SKY-G211", critical},
		"shadowed numeric name":               {"func H(w http.ResponseWriter, r *http.Request) {\n\tvar id int\n\t_ = id\n\tfunc() {\n\t\tid := r.FormValue(\"id\")\n\t\tgdb.Exec(\"DELETE FROM t WHERE id = \" + id)\n\t}()\n}\n", "SKY-G211", critical},
		"placeholders":                        {"func (h *Handler) H(c *gin.Context) {\n\th.repo.pool.Query(c, \"SELECT * FROM t WHERE n = $1\", c.Query(\"n\"))\n\tgdb.Where(\"name = ?\", c.Query(\"n\")).Find(nil)\n\th.repo.db.QueryContext(c, \"SELECT 1 WHERE ? = ?\", c.Query(\"a\"), c.Query(\"b\"))\n}\n", "SKY-G211", nil},
		"gorm struct and map conditions":      {"func H(c *gin.Context) {\n\tgdb.Where(&listQuery{Sort: c.Query(\"s\")}).Find(nil)\n\tgdb.Where(map[string]any{\"sort\": c.Query(\"s\")}).Find(nil)\n}\n", "SKY-G211", nil},
		"numbers cannot inject":               {"func H(c *gin.Context) {\n\tid, _ := strconv.Atoi(c.Param(\"id\"))\n\tgdb.Raw(fmt.Sprintf(\"SELECT * FROM t WHERE id = %d\", id))\n\tvar q listQuery\n\tc.ShouldBindQuery(&q)\n\tgdb.Raw(fmt.Sprintf(\"SELECT * FROM t LIMIT %v\", q.Limit))\n\tgdb.First(nil, id)\n\tu, _ := uuid.Parse(c.Param(\"u\"))\n\tgdb.Raw(fmt.Sprintf(\"SELECT * FROM t WHERE u = '%s'\", u))\n}\n", "SKY-G211", nil},
		"local package named sqlx":            {"func H(w http.ResponseWriter, r *http.Request) {\n\tidx := sqlx.New()\n\tvar out []string\n\tidx.Select(&out, \"SELECT * FROM t WHERE n = '\"+r.FormValue(\"n\")+\"'\")\n\tsqlx.Select(idx, &out, \"SELECT * FROM t WHERE n = '\"+r.FormValue(\"n\")+\"'\")\n}\n", "SKY-G211", nil},
		"query formatted into a variable":     {"func (p *Repo) Get(uid string) {\n\tq := fmt.Sprintf(\"SELECT * FROM t WHERE id = %s\", uid)\n\tp.db.Query(q)\n\tsafe := \"SELECT * FROM t WHERE id = ?\"\n\tp.db.Query(safe, uid)\n}\n", "SKY-G211", []string{"HIGH"}},
		"prepared statement arguments":        {"func H(w http.ResponseWriter, r *http.Request, stmt *sql.Stmt) { stmt.Exec(r.FormValue(\"id\")) }\n", "SKY-G211", nil},
	})
}

// Look-alikes of the barriers above must not hide a finding.
func TestBarrierLookalikesStillReport(t *testing.T) {
	cases := map[string]struct {
		source string
		rule   string
		want   []string
	}{
		"strconv alias of another package": {"package app\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n\n\tstrconv \"example.com/app/conv\"\n)\n\nvar db *sql.DB\n\n" +
			"func H(w http.ResponseWriter, r *http.Request) { db.Query(\"SELECT * FROM t WHERE id = \" + strconv.Atoi(r.FormValue(\"id\"))) }\n", "SKY-G211", []string{"CRITICAL"}},
		"gorm condition of unknown type": {"package app\n\nimport (\n\t\"example.com/app/helper\"\n\t\"github.com/gin-gonic/gin\"\n\t\"gorm.io/gorm\"\n)\n\nvar gdb *gorm.DB\n\n" +
			"func H(c *gin.Context) { gdb.Where(helper.Cond(c.Query(\"q\"))).Find(nil) }\n", "SKY-G211", []string{"CRITICAL"}},
		"Sanitize and Cookie on other types": {"package app\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\n\t\"github.com/microcosm-cc/bluemonday\"\n)\n\nvar _ = bluemonday.UGCPolicy\n\n" +
			"type cleaner struct{}\n\nfunc (cleaner) Sanitize(s string) string { return s }\n\nfunc (cleaner) Cookie(s string) string { return s }\n\n" +
			"func H(w http.ResponseWriter, r *http.Request) {\n\tvar p cleaner\n\tfmt.Fprintf(w, \"<p>%s</p>\", p.Sanitize(r.FormValue(\"q\")))\n\tfmt.Fprintf(w, \"<p>%s</p>\", p.Cookie(r.FormValue(\"q\")))\n}\n", "SKY-G228", []string{"HIGH", "HIGH"}},
		"real bluemonday policy": {"package app\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\n\t\"github.com/microcosm-cc/bluemonday\"\n)\n\nvar policy = bluemonday.UGCPolicy()\n\n" +
			"func H(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, \"<p>%s</p>\", policy.Sanitize(r.FormValue(\"q\"))) }\n", "SKY-G228", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := severitiesFor(t, map[string]string{"app.go": tc.source}, tc.rule)
			assertSeverities(t, got, tc.want)
		})
	}
}

func TestXSSResponsesAndTemplates(t *testing.T) {
	high := []string{"HIGH"}
	runSinkCases(t, map[string]sinkCase{
		"template.HTML from the request":       {"func H(w http.ResponseWriter, r *http.Request) { page.Execute(w, template.HTML(r.FormValue(\"bio\"))) }\n", "SKY-G226", []string{"CRITICAL"}},
		"template.HTML of escaped text":        {"func H(w http.ResponseWriter, r *http.Request) { page.Execute(w, template.HTML(\"<b>\"+html.EscapeString(r.FormValue(\"n\"))+\"</b>\")) }\n", "SKY-G226", nil},
		"fprintf into html":                    {"func H(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, \"<h1>%s</h1>\", r.FormValue(\"q\")) }\n", "SKY-G228", high},
		"raw bytes are sniffed":                {"func H(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.FormValue(\"q\"))) }\n", "SKY-G228", high},
		"escaped but the raw value is written": {"func H(w http.ResponseWriter, r *http.Request) {\n\tq := r.FormValue(\"q\")\n\t_ = html.EscapeString(q)\n\tfmt.Fprintf(w, \"<p>%s</p>\", q)\n}\n", "SKY-G228", high},
		"content type set on another writer":   {"func H(w http.ResponseWriter, other http.ResponseWriter, r *http.Request) {\n\tother.Header().Set(\"Content-Type\", \"application/json\")\n\tfmt.Fprintf(w, \"<p>%s</p>\", r.FormValue(\"q\"))\n}\n", "SKY-G228", high},
		"content type chosen by the request":   {"func H(w http.ResponseWriter, r *http.Request) {\n\tw.Header().Set(\"Content-Type\", r.FormValue(\"ct\"))\n\tw.Write([]byte(r.FormValue(\"b\")))\n}\n", "SKY-G228", high},
		"content type set after the write":     {"func H(w http.ResponseWriter, r *http.Request) {\n\tw.Write([]byte(r.FormValue(\"q\")))\n\tw.Header().Set(\"Content-Type\", \"text/plain\")\n}\n", "SKY-G228", high},
		"html written before text":             {"func H(w http.ResponseWriter, r *http.Request) {\n\tfmt.Fprint(w, \"<html><body>\")\n\tfmt.Fprintf(w, \"Hello %s\", r.FormValue(\"n\"))\n}\n", "SKY-G228", high},
		"html assembled in a builder":          {"func H(w http.ResponseWriter, r *http.Request) {\n\tvar sb strings.Builder\n\tsb.WriteString(\"<li>\" + r.FormValue(\"i\") + \"</li>\")\n\tio.WriteString(w, sb.String())\n}\n", "SKY-G228", high},
		"gin data with html type":              {"func H(c *gin.Context) { c.Data(200, \"text/html\", []byte(c.Query(\"q\"))) }\n", "SKY-G228", high},
		"gin string after html type":           {"func H(c *gin.Context) {\n\tc.Header(\"Content-Type\", \"text/html\")\n\tc.String(200, c.Query(\"q\"))\n}\n", "SKY-G228", high},
		"echo html":                            {"func H(c echo.Context) error { return c.HTML(200, \"<h1>\"+c.QueryParam(\"t\")+\"</h1>\") }\n", "SKY-G228", high},
		"fiber after html type":                {"func H(c *fiber.Ctx) error {\n\tc.Type(\"html\")\n\treturn c.SendString(\"<p>\" + c.Query(\"q\") + \"</p>\")\n}\n", "SKY-G228", high},
		"non-html or escaped responses": {"func H(w http.ResponseWriter, r *http.Request) {\n\tw.Header().Set(\"Content-Type\", \"application/json\")\n\tjson.NewEncoder(w).Encode(r.FormValue(\"q\"))\n\tfmt.Fprintf(w, \"%s\", r.FormValue(\"q\"))\n}\n\n" +
			"func E(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, \"<p>%s</p>\", html.EscapeString(r.FormValue(\"q\"))) }\n\n" +
			"func M(w http.ResponseWriter, r *http.Request) { b, _ := json.Marshal(r.FormValue(\"q\")); w.Write(b) }\n\n" +
			"func T(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, \"Hello, %s!\", r.FormValue(\"n\")) }\n\n" +
			"func C(w http.ResponseWriter, r *http.Request) { c, _ := r.Cookie(\"theme\"); fmt.Fprintf(w, \"<body class=%q>\", c.Value) }\n\n" +
			"func D(w http.ResponseWriter, r *http.Request) {\n\tvar v struct{ A string }\n\tif err := json.NewDecoder(r.Body).Decode(&v); err != nil {\n\t\tw.Write([]byte(err.Error()))\n\t}\n}\n", "SKY-G228", nil},
		"framework text responses": {"func G(c *gin.Context) { c.String(200, \"hi %s\", c.Query(\"q\")); c.JSON(200, c.Query(\"q\")) }\n\n" +
			"func E(c echo.Context) error { return c.String(200, c.QueryParam(\"q\")) }\n\n" +
			"func F(c *fiber.Ctx) error { return c.SendString(\"you searched \" + c.Query(\"q\")) }\n", "SKY-G228", nil},
		"writers that are not responses": {"func H(w http.ResponseWriter, r *http.Request) {\n\tfmt.Fprintf(os.Stdout, \"<p>%s</p>\", r.FormValue(\"q\"))\n\tvar sb strings.Builder\n\tfmt.Fprintf(&sb, \"<p>%s</p>\", r.FormValue(\"q\"))\n}\n", "SKY-G228", nil},
	})
}

func TestFrameworkAndClientSinks(t *testing.T) {
	critical := []string{"CRITICAL"}
	high := []string{"HIGH"}
	runSinkCases(t, map[string]sinkCase{
		"package-level client":   {"func H(w http.ResponseWriter, r *http.Request) { client.Get(r.FormValue(\"u\")) }\n", "SKY-G216", critical},
		"client field":           {"func (h *Handler) H(w http.ResponseWriter, r *http.Request) { h.client.Post(r.FormValue(\"u\"), \"\", nil) }\n", "SKY-G216", critical},
		"default client":         {"func H(w http.ResponseWriter, r *http.Request) { http.DefaultClient.Head(r.Header.Get(\"X-T\")) }\n", "SKY-G216", critical},
		"reverse proxy target":   {"func H(w http.ResponseWriter, r *http.Request) {\n\tu, _ := url.Parse(r.FormValue(\"up\"))\n\thttputil.NewSingleHostReverseProxy(u)\n}\n", "SKY-G216", critical},
		"request host set later": {"func (h *Handler) H(w http.ResponseWriter, r *http.Request) {\n\treq, _ := http.NewRequest(\"GET\", \"http://x.internal/\", nil)\n\treq.URL.Host = r.FormValue(\"h\")\n\th.client.Do(req)\n}\n", "SKY-G216", critical},
		"fixed hosts":            {"func H(w http.ResponseWriter, r *http.Request) {\n\tclient.Get(\"https://api.example.com/u/\" + url.PathEscape(r.FormValue(\"id\")))\n\tu, _ := url.Parse(\"http://backend.internal/\")\n\thttputil.NewSingleHostReverseProxy(u)\n}\n", "SKY-G216", nil},
		"gin redirect":           {"func H(c *gin.Context) { c.Redirect(302, c.Query(\"next\")) }\n", "SKY-G220", high},
		"echo redirect":          {"func H(c echo.Context) error { return c.Redirect(302, c.QueryParam(\"to\")) }\n", "SKY-G220", high},
		"fiber redirect":         {"func H(c *fiber.Ctx) error { return c.Redirect(c.Query(\"next\")) }\n", "SKY-G220", high},
		"constant redirects":     {"func G(c *gin.Context) { c.Redirect(302, \"/login\") }\n\nfunc F(c *fiber.Ctx) error { return c.Redirect(\"/home\") }\n", "SKY-G220", nil},
		"gin file":               {"func H(c *gin.Context) { c.File(\"/srv/\" + c.Param(\"name\")) }\n", "SKY-G215", high},
		"fiber download":         {"func H(c *fiber.Ctx) error { return c.Download(\"./files/\" + c.Params(\"n\")) }\n", "SKY-G215", high},
		"read dir":               {"func H(w http.ResponseWriter, r *http.Request) { os.ReadDir(filepath.Join(\"/srv\", r.FormValue(\"d\"))) }\n", "SKY-G215", high},
		"base name files":        {"func G(c *gin.Context) { c.File(filepath.Join(\"/srv\", filepath.Base(c.Param(\"n\")))) }\n\nfunc E(c echo.Context) error { return c.Attachment(filepath.Base(c.QueryParam(\"f\")), \"r.pdf\") }\n", "SKY-G215", nil},
		"syscall exec":           {"func H(w http.ResponseWriter, r *http.Request) { syscall.Exec(r.FormValue(\"bin\"), nil, nil) }\n", "SKY-G212", critical},
		"ssh session":            {"func H(w http.ResponseWriter, r *http.Request) {\n\tconn, _ := ssh.Dial(\"tcp\", \"h:22\", nil)\n\ts, _ := conn.NewSession()\n\ts.Run(\"ls \" + r.FormValue(\"d\"))\n}\n", "SKY-G212", critical},
		"fixed commands":         {"func H(w http.ResponseWriter, r *http.Request) {\n\tsyscall.Exec(\"/usr/bin/uptime\", []string{\"uptime\"}, nil)\n\tconn, _ := ssh.Dial(\"tcp\", \"h:22\", nil)\n\ts, _ := conn.NewSession()\n\ts.Run(\"uptime\")\n}\n", "SKY-G212", nil},
	})
}

func TestFrameworkBindTargetsAreSources(t *testing.T) {
	high := []string{"HIGH"}
	runSinkCases(t, map[string]sinkCase{
		"gin ShouldBindQuery": {"func H(c *gin.Context) {\n\tvar q struct{ Path string }\n\tc.ShouldBindQuery(&q)\n\tos.ReadFile(q.Path)\n}\n", "SKY-G215", high},
		"gin ShouldBindUri":   {"func H(c *gin.Context) {\n\tvar p struct{ Path string }\n\tc.ShouldBindUri(&p)\n\tos.ReadFile(p.Path)\n}\n", "SKY-G215", high},
		"echo Bind":           {"func H(c echo.Context) error {\n\tvar p struct{ Path string }\n\tc.Bind(&p)\n\t_, err := os.ReadFile(p.Path)\n\treturn err\n}\n", "SKY-G215", high},
		"fiber QueryParser":   {"func H(c *fiber.Ctx) error {\n\tvar p struct{ Path string }\n\tc.QueryParser(&p)\n\t_, err := os.ReadFile(p.Path)\n\treturn err\n}\n", "SKY-G215", high},
		"unbound struct":      {"func H(c *gin.Context) {\n\tvar p struct{ Path string }\n\tos.ReadFile(p.Path)\n}\n", "SKY-G215", nil},
	})
}

# Source-only review draft: gorilla/mux and tiny-http

**Pending a different agent's independent review. No scanner outputs were read or compared, and no new scan was run.** Existing earlier scans make this a post-selection source review, not a new blind study. Freeze reviewed labels before rerunning the scanner.

Ledger: [SOURCE_LABELS_MUX_TINY_DRAFT.json](SOURCE_LABELS_MUX_TINY_DRAFT.json). SHA256: `4cae6e6bc308fad413c5d8af88626f2c643f6e8e8264d0c020f19f1a309af951`.

| Repository | Exact revision |
| --- | --- |
| [gorilla--mux](https://github.com/gorilla/mux) | `db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265` |
| [tiny-http--tiny-http](https://github.com/tiny-http/tiny-http) | `e2215636a73c7c3ac2d0a59d607454591f2cb2ac` |

The 33 selected facts contain 23 used declarations, one unused declaration, two declarations with unknown external use, three safe sink facts, one unsafe example sink, and three unresolved sink facts. Source hashes and declaration/consumer excerpts are attached to every row. No target tests, package scripts or code ran.

The sole unused method, `FusedReader::into_inner`, has no source consumers and no public export path through the private `util` module. It explicitly carries `#[allow(dead_code)]`: semantic truth is UNUSED, intention is KEEP. Its absence from findings must not become a false safety claim or an automatic-removal recommendation. This review found no justified unsuppressed private dead-code positive; it cannot measure useful dead-code recall.

The unsafe security fact is the deliberately broad `serve-root` example: request-selected file access lacks containment. Its example intent and deployment assumptions remain explicit. It does not establish a vulnerability in tiny-http core or a live service. Command negatives establish only the selected injection boundary; PHP/CGI semantics and trusted operator configuration are separate.

Tests and examples are legitimate consumers for repository liveness. Their security labels earn no absence credit unless the subsequent run proves that those files and the relevant detector paths were actually assessed. Unknown API demand, redirects and socket cleanup remain unscored.

| ID | Truth | Source | Evidence/limit |
| --- | --- | --- | --- |
| mux-router-use-interface | USED | [middleware.go:31](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/middleware.go#L31) | TestMiddlewareAdd constructs a Router and invokes this exact receiver method. Tests are legitimate consumers. |
| mux-route-use-interface | USED | [middleware.go:47](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/middleware.go#L47) | HandleFunc returns a Route and TestMiddlewareAdd invokes route.useInterface. Distinct from Router.useInterface. |
| mux-dummy-handler | USED | [middleware_test.go:21](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/middleware_test.go#L21) | Passed to Router.HandleFunc by a Go test; a direct function call is unnecessary. |
| mux-cors-method-helper | USED | [middleware.go:74](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/middleware.go#L74) | Called inside the handler closure returned by public CORSMethodMiddleware. |
| mux-clean-path | USED | [mux.go:524](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L524) | Router.ServeHTTP directly calls it when cleaning is enabled. |
| mux-replace-url-path | USED | [mux.go:542](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L542) | Called by Router.ServeHTTP and regexp route handling. |
| mux-method-not-allowed | USED | [mux.go:670](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L670) | Converted to http.HandlerFunc by a factory called from ServeHTTP. |
| mux-method-not-allowed-factory | USED | [mux.go:676](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L676) | Called from ServeHTTP on unmatched method. |
| mux-request-with-router | USED | [mux.go:513](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L513) | Called from Router.ServeHTTP before dispatch. |
| mux-query-key | USED | [regexp.go:257](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/regexp.go#L257) | Called with request query and route key by getURLQuery. |
| mux-match-query | USED | [regexp.go:293](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/regexp.go#L293) | routeRegexp.Match selects and invokes the query matcher. |
| mux-test-methods | USED | [mux_test.go:1978](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux_test.go#L1978) | Directly called by the table-driven test. |
| mux-set-url-vars | USED | [test_helpers.go:17](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/test_helpers.go#L17) | ExampleSetURLVars directly calls this API. Production file hosts helper usable by external tests. |
| mux-get-route-public | UNKNOWN | [mux.go:238](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L238) | No local calls found, but exported on public Router. Compatibility documentation plus unknown external consumers prevents unused proof. |
| tiny-registration-new | USED | [src/util/task_pool.rs:37](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/util/task_pool.rs#L37) | TaskPool.add_thread constructs Registration as a scope guard. |
| tiny-add-thread | USED | [src/util/task_pool.rs:80](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/util/task_pool.rs#L80) | TaskPool.new and spawn call add_thread; Server constructs TaskPool. |
| tiny-parse-header | USED | [src/util/mod.rs:25](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/util/mod.rs#L25) | Response transfer encoding and unit test call this function. |
| tiny-build-date | USED | [src/response.rs:74](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/response.rs#L74) | Response print path calls it to insert Date. |
| tiny-fused-new | USED | [src/util/fused_reader.rs:12](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/util/fused_reader.rs#L12) | Request construction wraps a reader then erases it to a Read trait object. |
| tiny-extract-writer | USED | [src/request.rs:407](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/request.rs#L407) | Public into_writer and response path call this method. |
| tiny-parse-http-version | USED | [src/client.rs:269](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/client.rs#L269) | parse_request_line invokes it; ClientConnection.read calls parse_request_line. |
| tiny-read-next-line | USED | [src/client.rs:80](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/client.rs#L80) | Request reading calls it for the initial line and headers. |
| tiny-content-type | USED | [examples/serve-root.rs:8](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/examples/serve-root.rs#L8) | Example main calls it to build the response header. |
| tiny-header-unit-test | USED | [src/util/mod.rs:53](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/util/mod.rs#L53) | cfg(test) and #[test] register this function with the Rust test harness; no tests executed. |
| tiny-fused-into-inner | UNUSED; intentional keep | [src/util/fused_reader.rs:17](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/util/fused_reader.rs#L17) | Sole into_inner token in all tracked Rust source is declaration. util is private; FusedReader re-export remains inside util and consumers erase it behind Read. Explicit allow(dead_code) affects reporting policy, not semantic no-use truth. |
| tiny-num-connections | UNKNOWN | [src/lib.rs:411](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/lib.rs#L411) | No local consumer; public Server method has unknown external demand. unimplemented body is a quality question, not dead-code proof. |
| mux-literal-http-body | SAFE | [mux_httpserver_test.go:17](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux_httpserver_test.go#L17) | Write argument is fixed literal bytes; request data cannot contribute HTML at this sink. |
| mux-clean-redirect | UNKNOWN | [mux.go:196](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/mux.go#L196) | Location copies req.URL and changes path. URL authority, serialization and caller construction prevent a complete same-origin proof from this bounded review. |
| mux-slash-redirect | UNKNOWN | [regexp.go:380](https://github.com/gorilla/mux/blob/db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265/regexp.go#L380) | StrictSlash changes request path then invokes replaceURLPath and RedirectHandler; same unresolved authority/caller assumptions. |
| tiny-example-file-read | UNSAFE | [examples/serve-root.rs:42](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/examples/serve-root.rs#L42) | Deliberately broad serve-root example opens request path and returns the file without a serving-root boundary, allowlist or containment check. Unsafe filesystem exposure if run for untrusted clients; not a deployed-service or core-library vulnerability claim. |
| tiny-php-command | SAFE | [examples/php-cgi.rs:18](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/examples/php-cgi.rs#L18) | Fixed php-cgi program; script separate argv from operator startup arguments. Request URL becomes CGI environment data, not executable/script choice or shell code. No shell is invoked. |
| tiny-curl-command | SAFE | [benches/bench.rs:19](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/benches/bench.rs#L19) | Fixed curl executable, separate arguments, localhost URL, local assigned port and literal request count; no shell or request input. |
| tiny-unix-cleanup | UNKNOWN | [src/lib.rs:478](https://github.com/tiny-http/tiny-http/blob/e2215636a73c7c3ac2d0a59d607454591f2cb2ac/src/lib.rs#L478) | Unix socket pathname from listener configuration reaches remove_file in Server.drop. Ownership/replacement and operator configuration assumptions remain unresolved; no request influence established. |

Reviewer checks: verify the exact declaration and consumer owner, assess bounded no-use proof and public export paths, challenge safe/unsafe trust assumptions, and record disagreements separately. This is a purposive sample with no whole-repository recall guarantee.

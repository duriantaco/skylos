from __future__ import annotations

REQUEST_SUPERGLOBALS = frozenset({"$_GET", "$_POST", "$_REQUEST", "$_COOKIE"})
SERVER_SUPERGLOBAL = "$_SERVER"
PATH_SERVER_KEYS = frozenset({"PHP_SELF", "PATH_INFO", "ORIG_PATH_INFO"})
DYNAMIC_SUPERGLOBALS = frozenset(
    {
        "$_GET",
        "$_POST",
        "$_REQUEST",
        "$_COOKIE",
        "$_FILES",
        "$_SERVER",
        "$_ENV",
        "$_SESSION",
        "$GLOBALS",
    }
)
FILES_SERVER_KEYS = frozenset({"tmp_name", "size", "error"})
USER_CONTROLLED_SERVER_KEYS = frozenset(
    {
        "REQUEST_URI",
        "UNENCODED_URL",
        "DOCUMENT_URI",
        "QUERY_STRING",
        "argv",
        "PATH_INFO",
        "ORIG_PATH_INFO",
        "PATH_TRANSLATED",
        "ORIG_PATH_TRANSLATED",
        "ORIG_SCRIPT_NAME",
        "ORIG_SCRIPT_FILENAME",
        "PHP_SELF",
        "SCRIPT_URI",
        "SCRIPT_URL",
        "REDIRECT_URL",
        "REQUEST_METHOD",
        "CONTENT_TYPE",
        "PHP_AUTH_USER",
        "PHP_AUTH_PW",
        "PHP_AUTH_DIGEST",
    }
)

TYPED_FILTERS = frozenset(
    {
        "FILTER_VALIDATE_INT",
        "FILTER_VALIDATE_FLOAT",
        "FILTER_VALIDATE_BOOLEAN",
        "FILTER_VALIDATE_BOOL",
        "FILTER_SANITIZE_NUMBER_INT",
    }
)
HTML_FILTERS = frozenset(
    {"FILTER_SANITIZE_SPECIAL_CHARS", "FILTER_SANITIZE_FULL_SPECIAL_CHARS"}
)

SOURCE_FUNCTIONS = frozenset({"getallheaders", "apache_request_headers"})
SOURCE_FUNCTIONS_WITH_ARGUMENT = frozenset({"request", "old", "get_query_var"})
INPUT_STREAM_READERS = frozenset({"file_get_contents", "fopen"})

REQUEST_VARIABLE_NAMES = frozenset({"$request", "$req"})
REQUEST_TYPE_SUFFIXES = ("request", "requestinterface")
REQUEST_SOURCE_METHODS = frozenset(
    {
        "input",
        "query",
        "post",
        "get",
        "all",
        "only",
        "except",
        "header",
        "cookie",
        "string",
        "str",
        "json",
        "validated",
        "safe",
        "collect",
        "fullUrl",
        "fullUrlWithQuery",
        "getContent",
        "getQueryString",
        "getRequestUri",
        "getPathInfo",
        "getUri",
        "getQueryParams",
        "getParsedBody",
        "getCookieParams",
        "getHeader",
        "getHeaderLine",
        "getBody",
        "getGet",
        "getPost",
        "getVar",
        "getGetPost",
        "getPostGet",
        "getJSON",
        "getJsonVar",
        "getRawInput",
        "getRawInputVar",
        "getCookie",
        "getData",
        "getQuery",
        "getParam",
        "getQueryParam",
        "getBodyParam",
        "getBodyParams",
        "getRawBody",
    }
)
REQUEST_SOURCE_METHODS_WITH_ARGUMENT = frozenset({"route"})
CODEIGNITER_INPUT_METHODS = frozenset(
    {
        "get",
        "post",
        "get_post",
        "post_get",
        "cookie",
        "user_agent",
        "request_headers",
        "get_request_header",
        "input_stream",
    }
)
REQUEST_OBJECT_BAGS = frozenset({"headers", "attributes", "files"})
REQUEST_FACADES = frozenset(
    {"request", "illuminate\\support\\facades\\request", "illuminate\\http\\request"}
)
REQUEST_FACTORIES = frozenset(
    {"getCurrentRequest", "getMainRequest", "getMasterRequest"}
)
UPLOAD_NAME_METHODS = frozenset(
    {
        "getClientOriginalName",
        "getClientOriginalExtension",
        "getClientMimeType",
        "getClientFilename",
        "getClientMediaType",
    }
)

NUMERIC_RESULT_FUNCTIONS = frozenset(
    {
        "intval",
        "floatval",
        "doubleval",
        "boolval",
        "abs",
        "round",
        "floor",
        "ceil",
        "count",
        "sizeof",
        "strlen",
        "mb_strlen",
        "md5",
        "sha1",
        "crc32",
        "hash",
        "hash_hmac",
        "password_hash",
        "password_verify",
        "hash_equals",
        "base64_encode",
        "bin2hex",
        "dechex",
        "hexdec",
        "bindec",
        "decbin",
        "octdec",
        "decoct",
        "number_format",
        "absint",
        "isset",
        "empty",
        "is_numeric",
        "is_int",
        "is_integer",
        "is_float",
        "is_string",
        "is_array",
        "is_bool",
        "is_null",
        "is_object",
        "in_array",
        "array_key_exists",
        "ctype_digit",
        "ctype_alnum",
        "ctype_alpha",
        "ctype_xdigit",
        "ctype_lower",
        "ctype_upper",
        "ctype_space",
        "strcmp",
        "strcasecmp",
        "strncmp",
        "strncasecmp",
        "strpos",
        "stripos",
        "strrpos",
        "str_contains",
        "str_starts_with",
        "str_ends_with",
        "preg_match",
        "preg_match_all",
        "checkdate",
        "file_exists",
        "is_file",
        "is_dir",
        "is_readable",
        "is_writable",
        "filesize",
        "filemtime",
        "strtotime",
        "time",
        "mt_rand",
        "rand",
        "random_int",
        "ord",
        "levenshtein",
        "similar_text",
        "uniqid",
        "sanitize_key",
        "wp_verify_nonce",
        "current_user_can",
        "json_last_error",
    }
)
LOOKUP_FUNCTIONS = frozenset(
    {
        "mysqli_query",
        "mysql_query",
        "pg_query",
        "pg_query_params",
        "mysqli_fetch_assoc",
        "mysqli_fetch_array",
        "mysqli_fetch_row",
        "mysqli_fetch_object",
        "mysqli_fetch_all",
        "mysql_fetch_assoc",
        "mysql_fetch_array",
        "mysql_fetch_row",
        "mysql_fetch_object",
        "pg_fetch_assoc",
        "pg_fetch_array",
        "pg_fetch_row",
        "pg_fetch_object",
        "pg_fetch_all",
        "get_post",
        "get_userdata",
        "get_user_by",
        "get_option",
        "get_post_meta",
        "get_user_meta",
        "get_term",
    }
)
RECEIVER_ONLY_METHODS = frozenset(
    {
        "find",
        "findOrFail",
        "findMany",
        "first",
        "firstOrFail",
        "exists",
        "count",
        "get",
        "where",
        "orWhere",
        "whereIn",
        "whereNotIn",
        "whereBetween",
        "orderBy",
        "orderByDesc",
        "latest",
        "oldest",
        "limit",
        "offset",
        "take",
        "skip",
        "with",
        "select",
        "groupBy",
        "having",
        "join",
        "leftJoin",
        "paginate",
        "simplePaginate",
        "pluck",
        "value",
        "query",
        "execute",
        "prepare",
        "fetch",
        "fetchAll",
        "fetchColumn",
        "fetchObject",
        "fetch_assoc",
        "fetch_array",
        "fetch_row",
        "fetch_object",
        "fetch_all",
        "get_results",
        "get_row",
        "get_var",
        "get_col",
        "executeQuery",
        "fetchAssociative",
        "fetchAllAssociative",
        "fetchOne",
        "getResult",
        "getOneOrNullResult",
        "getSingleResult",
    }
)
TYPED_REQUEST_METHODS = frozenset(
    {
        "has",
        "filled",
        "missing",
        "boolean",
        "integer",
        "float",
        "date",
        "enum",
        "isMethod",
        "ajax",
        "user",
        "ip",
        "hasFile",
        "isValid",
        "file",
        "method",
        "isSecure",
        "wantsJson",
        "expectsJson",
    }
)

PURE_STRING_FUNCTIONS = frozenset(
    {
        "sprintf",
        "vsprintf",
        "implode",
        "join",
        "trim",
        "ltrim",
        "rtrim",
        "strtolower",
        "strtoupper",
        "ucfirst",
        "lcfirst",
        "str_replace",
        "substr",
        "basename",
        "dirname",
        "escapeshellcmd",
        "str_pad",
        "str_repeat",
    }
)

HTML_ESCAPERS = frozenset(
    {
        "htmlspecialchars",
        "htmlentities",
        "esc_html",
        "esc_attr",
        "esc_textarea",
        "esc_html__",
        "esc_attr__",
        "esc_html_x",
        "esc_attr_x",
        "e",
        "twig_escape_filter",
    }
)
HTML_BODY_FILTERS = frozenset(
    {
        "strip_tags",
        "sanitize_text_field",
        "wp_kses",
        "wp_kses_post",
        "wp_kses_data",
        "xss_clean",
    }
)
URL_ENCODERS = frozenset({"urlencode", "rawurlencode", "http_build_query", "esc_url"})
SHELL_ESCAPERS = frozenset({"escapeshellarg"})
SQL_QUOTERS = frozenset({"pg_escape_literal", "pg_escape_identifier"})
SQL_ESCAPERS = frozenset(
    {
        "mysqli_real_escape_string",
        "mysqli_escape_string",
        "mysql_real_escape_string",
        "mysql_escape_string",
        "addslashes",
        "esc_sql",
        "pg_escape_string",
        "sqlite_escape_string",
        "db2_escape_string",
        "cubrid_real_escape_string",
    }
)
SQL_QUOTER_METHODS = frozenset({"quote"})
SQL_ESCAPER_METHODS = frozenset(
    {"real_escape_string", "escape_string", "escapeString", "_real_escape", "_escape"}
)
HTML_ESCAPER_METHODS = frozenset({"escapeHtml", "escapeHtmlAttr"})
URL_ESCAPER_METHODS = frozenset({"escapeUrl"})

COMMAND_FUNCTIONS = frozenset(
    {"exec", "system", "shell_exec", "passthru", "popen", "proc_open"}
)
PROGRAM_FUNCTIONS = frozenset({"pcntl_exec"})
CODE_FUNCTIONS = frozenset({"eval", "create_function"})
TERMINATING_FUNCTIONS = frozenset({"die", "exit", "wp_die", "abort"})
GUARD_FUNCTIONS = frozenset(
    {
        "in_array",
        "array_key_exists",
        "ctype_digit",
        "ctype_alnum",
        "ctype_alpha",
        "ctype_xdigit",
        "is_numeric",
        "is_int",
        "is_integer",
        "is_float",
    }
)

DEBUG_OUTPUT_FUNCTIONS = frozenset({"print_r", "var_export"})

SQL_FUNCTION_SINKS = {
    "mysql_query": 0,
    "mysql_unbuffered_query": 0,
    "mysql_db_query": 1,
    "mysqli_query": 1,
    "mysqli_real_query": 1,
    "mysqli_multi_query": 1,
    "mysqli_prepare": 1,
    "mysqli_execute_query": 1,
    "pg_send_query": 1,
    "pg_prepare": 2,
    "sqlsrv_query": 1,
    "sqlsrv_prepare": 1,
    "oci_parse": 1,
    "odbc_exec": 1,
    "odbc_prepare": 1,
    "db2_exec": 1,
    "db2_prepare": 1,
    "db_query": 0,
    "db_query_range": 0,
}
SQL_CONNECTION_FIRST_FUNCTIONS = {"pg_query": 2, "pg_query_params": 3}
SQL_METHOD_SINKS = frozenset(
    {
        "query",
        "queryRange",
        "where",
        "multi_query",
        "real_query",
        "prepare",
        "executeQuery",
        "executeStatement",
        "executeUpdate",
        "createQuery",
        "createNativeQuery",
        "querySingle",
        "whereRaw",
        "orWhereRaw",
        "havingRaw",
        "orHavingRaw",
        "orderByRaw",
        "groupByRaw",
        "selectRaw",
        "fromRaw",
    }
)
SQL_RECEIVER_METHOD_SINKS = frozenset({"exec"})
SQL_RECEIVER_NAMES = (
    "pdo",
    "db",
    "dbh",
    "conn",
    "connection",
    "database",
    "sqlite",
    "mysqli",
    "link",
)
WPDB_METHOD_SINKS = frozenset({"get_results", "get_row", "get_var", "get_col"})
DB_FACADES = frozenset(
    {
        "db",
        "illuminate\\support\\facades\\db",
        "illuminate\\database\\capsule\\manager",
        "capsule",
    }
)
DB_FACADE_SINKS = frozenset(
    {
        "raw",
        "select",
        "selectOne",
        "selectFromWriteConnection",
        "insert",
        "update",
        "delete",
        "statement",
        "unprepared",
        "affectingStatement",
        "cursor",
        "scalar",
    }
)

URL_FUNCTION_SINKS = {"curl_init": 0, "get_headers": 0, "fsockopen": 0}
HTTP_FACADES = frozenset({"http", "illuminate\\support\\facades\\http"})
HTTP_FACADE_URL_ARGUMENT = {
    "get": 0,
    "post": 0,
    "put": 0,
    "patch": 0,
    "delete": 0,
    "head": 0,
    "send": 1,
}

STATIC_ALL_SANITIZERS = {("illuminate\\support\\str", "slug"), ("str", "slug")}
CASE_FUNCTIONS = frozenset(
    {
        "strtolower",
        "strtoupper",
        "mb_strtolower",
        "mb_strtoupper",
        "trim",
        "ltrim",
        "rtrim",
    }
)

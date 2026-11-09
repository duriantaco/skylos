"""ASP.NET request sources and receiver-typed sinks for the C# taint scan.

Sources follow CodeQL's ASP.NET Core remote-flow model and SecurityCodeScan's
default taint entry points: controller actions, Razor Page handlers, minimal
API handlers and request accessors, never constructor (dependency injection)
or plain service parameters. Ambiguous sink names (``GetAsync``, ``Query``,
``Deserialize``) count only on a receiver whose declared type is known.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str


COMMAND = Rule(
    "SKY-D212",
    "CRITICAL",
    "Process execution uses request-controlled data. Use a fixed executable "
    "and validate or allowlist the arguments.",
)
PATH = Rule(
    "SKY-D215",
    "HIGH",
    "Request-controlled path reaches a filesystem API. Join Path.GetFileName(...) "
    "to a fixed directory or check the full path stays inside it.",
)
SSRF = Rule(
    "SKY-D216",
    "CRITICAL",
    "Request-controlled URL reaches an outbound HTTP request. Validate the "
    "scheme and host against an allowlist.",
)
SQL = Rule(
    "SKY-D211",
    "CRITICAL",
    "SQL command text uses request-controlled data. Use parameters "
    "(SqlParameter, FromSqlInterpolated or Dapper parameters).",
)
SQL_BUILT = Rule(
    "SKY-D211",
    "HIGH",
    "SQL command text is built from a method parameter by concatenation or "
    "interpolation. Use parameters; callers may pass request data.",
)
REDIRECT = Rule(
    "SKY-D230",
    "HIGH",
    "Redirect target uses request-controlled data. Use LocalRedirect or check "
    "Url.IsLocalUrl first.",
)
DESERIALIZE_REQUEST = Rule(
    "SKY-D233",
    "CRITICAL",
    "Request data is deserialized with a formatter that can create any type "
    "(BinaryFormatter family). Use System.Text.Json or a data-only format.",
)
DESERIALIZE = Rule(
    "SKY-D233",
    "HIGH",
    "BinaryFormatter-family deserializers can run code from the payload. Use "
    "System.Text.Json or a data-only format.",
)
TYPE_NAME_HANDLING = Rule(
    "SKY-D233",
    "HIGH",
    "Json.NET TypeNameHandling other than None lets the payload choose the .NET "
    "type to create. Use TypeNameHandling.None or an allowlisting "
    "ISerializationBinder.",
)
TYPE_NAME_HANDLING_BOUND = Rule(
    "SKY-D233",
    "MEDIUM",
    "Json.NET TypeNameHandling other than None with a SerializationBinder; make "
    "sure the binder only allows expected types.",
)
TYPE_RESOLVER = Rule(
    "SKY-D233",
    "HIGH",
    "JavaScriptSerializer with SimpleTypeResolver lets the payload choose the "
    "type to create. Remove the type resolver.",
)
XSS_TRUSTED = Rule(
    "SKY-D226",
    "HIGH",
    "Request-controlled data is marked as trusted HTML (HtmlString, Html.Raw or "
    "MarkupString). Encode it or run an HTML sanitizer first.",
)
XSS_RESPONSE = Rule(
    "SKY-D228",
    "HIGH",
    "Request-controlled data is written into an HTML response without encoding.",
)

XSS_KEY = "xss"
TAINT_KEYS = (
    COMMAND.rule_id,
    PATH.rule_id,
    SSRF.rule_id,
    SQL.rule_id,
    REDIRECT.rule_id,
    DESERIALIZE.rule_id,
    XSS_KEY,
)

CONTROLLER_ATTRIBUTES = frozenset({"ApiController", "Controller"})
CONTROLLER_BASES = frozenset(
    {"Controller", "ControllerBase", "ApiController", "ODataController"}
)
NON_ACTION_ATTRIBUTES = frozenset({"NonAction", "NonHandler"})
BINDING_ATTRIBUTES = frozenset(
    {
        "FromQuery",
        "FromBody",
        "FromRoute",
        "FromForm",
        "FromHeader",
        "FromUri",
        "AsParameters",
        "HttpTrigger",
        "Bind",
        "ModelBinder",
    }
)
SERVICE_ATTRIBUTES = frozenset({"FromServices", "FromKeyedServices", "Inject"})
BOUND_PROPERTY_ATTRIBUTES = frozenset(
    {
        "BindProperty",
        "SupplyParameterFromQuery",
        "SupplyParameterFromForm",
        "FromQuery",
        "FromRoute",
        "FromForm",
        "FromBody",
        "FromHeader",
    }
)

SCALAR_TYPES = frozenset(
    {
        "bool",
        "byte",
        "sbyte",
        "short",
        "ushort",
        "int",
        "uint",
        "long",
        "ulong",
        "nint",
        "nuint",
        "float",
        "double",
        "decimal",
        "Boolean",
        "Byte",
        "SByte",
        "Int16",
        "UInt16",
        "Int32",
        "UInt32",
        "Int64",
        "UInt64",
        "Single",
        "Double",
        "Decimal",
        "Guid",
        "DateTime",
        "DateTimeOffset",
        "DateOnly",
        "TimeOnly",
        "TimeSpan",
    }
)
REQUEST_OBJECT_TYPES = frozenset({"HttpRequest", "HttpRequestData", "HttpRequestBase"})
NON_INPUT_TYPES = frozenset(
    {
        "CancellationToken",
        "HttpContext",
        "HttpResponse",
        "HttpResponseData",
        "ClaimsPrincipal",
        "FunctionContext",
        "ExecutionContext",
        "HttpClient",
        "LinkGenerator",
        "RequestDelegate",
        "ModelStateDictionary",
        "ActionContext",
        "ControllerContext",
        "SqlConnection",
        "DbConnection",
        "NpgsqlConnection",
        "MySqlConnection",
        "SqliteConnection",
    }
)
INPUT_INTERFACES = frozenset(
    {
        "IFormFile",
        "IFormFileCollection",
        "IFormCollection",
        "IEnumerable",
        "IList",
        "ICollection",
        "IReadOnlyList",
        "IReadOnlyCollection",
        "IDictionary",
        "IReadOnlyDictionary",
        "IAsyncEnumerable",
    }
)
SERVICE_TYPE_SUFFIXES = (
    "Service",
    "Repository",
    "DbContext",
    "Factory",
    "Logger",
    "Provider",
    "HttpClient",
)

HTTP_CLIENT_TYPES = frozenset({"HttpClient", "HttpMessageInvoker"})
URL_HELPER_TYPES = frozenset({"IUrlHelper", "UrlHelper"})
HTTP_CLIENT_URL_METHODS = frozenset(
    {
        "GetAsync",
        "PostAsync",
        "PutAsync",
        "PatchAsync",
        "DeleteAsync",
        "GetStringAsync",
        "GetStreamAsync",
        "GetByteArrayAsync",
        "GetFromJsonAsync",
        "PostAsJsonAsync",
        "PutAsJsonAsync",
        "PatchAsJsonAsync",
        "DeleteFromJsonAsync",
    }
)
WEB_CLIENT_TYPES = frozenset({"WebClient"})
WEB_CLIENT_URL_METHODS = frozenset(
    {
        "DownloadString",
        "DownloadStringAsync",
        "DownloadStringTaskAsync",
        "DownloadData",
        "DownloadDataAsync",
        "DownloadDataTaskAsync",
        "DownloadFile",
        "DownloadFileAsync",
        "DownloadFileTaskAsync",
        "OpenRead",
        "OpenReadAsync",
        "OpenReadTaskAsync",
        "UploadString",
        "UploadStringAsync",
        "UploadStringTaskAsync",
        "UploadData",
        "UploadDataAsync",
        "UploadDataTaskAsync",
        "UploadFile",
        "UploadFileAsync",
        "UploadFileTaskAsync",
        "UploadValues",
        "UploadValuesAsync",
        "UploadValuesTaskAsync",
    }
)
SQL_COMMAND_TYPES = frozenset(
    {
        "SqlCommand",
        "DbCommand",
        "NpgsqlCommand",
        "MySqlCommand",
        "SqliteCommand",
        "SQLiteCommand",
        "OleDbCommand",
        "OdbcCommand",
        "OracleCommand",
        "SqlCeCommand",
    }
)
SQL_ADAPTER_TYPES = frozenset(
    {
        "SqlDataAdapter",
        "NpgsqlDataAdapter",
        "MySqlDataAdapter",
        "SQLiteDataAdapter",
        "OleDbDataAdapter",
        "OdbcDataAdapter",
        "OracleDataAdapter",
    }
)
DB_CONNECTION_TYPES = frozenset(
    {
        "IDbConnection",
        "DbConnection",
        "SqlConnection",
        "NpgsqlConnection",
        "MySqlConnection",
        "SqliteConnection",
        "SQLiteConnection",
        "OracleConnection",
        "OdbcConnection",
        "OleDbConnection",
        "SqlCeConnection",
    }
)
DAPPER_METHODS = frozenset(
    {
        "Query",
        "QueryAsync",
        "QueryFirst",
        "QueryFirstAsync",
        "QueryFirstOrDefault",
        "QueryFirstOrDefaultAsync",
        "QuerySingle",
        "QuerySingleAsync",
        "QuerySingleOrDefault",
        "QuerySingleOrDefaultAsync",
        "QueryMultiple",
        "QueryMultipleAsync",
        "Execute",
        "ExecuteAsync",
        "ExecuteScalar",
        "ExecuteScalarAsync",
        "ExecuteReader",
        "ExecuteReaderAsync",
    }
)
EF_RAW_SQL_METHODS = frozenset(
    {"FromSqlRaw", "ExecuteSqlRaw", "ExecuteSqlRawAsync", "SqlQueryRaw"}
)
EF_FORMATTABLE_SQL_METHODS = frozenset(
    {
        "FromSql",
        "SqlQuery",
        "ExecuteSql",
        "ExecuteSqlAsync",
        "ExecuteSqlCommand",
        "ExecuteSqlCommandAsync",
    }
)
EF6_STRING_SQL_METHODS = frozenset(
    {"SqlQuery", "ExecuteSqlCommand", "ExecuteSqlCommandAsync"}
)
UNSAFE_FORMATTER_TYPES = frozenset(
    {
        "BinaryFormatter",
        "SoapFormatter",
        "NetDataContractSerializer",
        "LosFormatter",
        "ObjectStateFormatter",
    }
)
UNSAFE_FORMATTER_METHODS = frozenset(
    {"Deserialize", "UnsafeDeserialize", "UnsafeDeserializeMethodResponse"}
)

REQUEST_MEMBERS = (
    r"(?:Query|QueryString|Form|Headers|Cookies|Body|BodyReader|RouteValues|Path|"
    r"PathInfo|Params|RawUrl|Url|UrlReferrer|Files|InputStream|ReadFormAsync|"
    r"ReadFromJsonAsync|RequestUri|GetQueryNameValuePairs|ServerVariables|UserAgent)"
)
SOURCE_HINT_RE = re.compile(
    r"\bRequest\s*\??\.\s*" + REQUEST_MEMBERS + r"\b"
    r"|\bRequest\s*\["
    r"|\bEnvironment\s*\.\s*GetEnvironmentVariable\b"
    r"|\bConsole\s*\.\s*ReadLine\b"
    r"|\bIFormFile\s*\.\s*FileName\b"
    r"|\bargs\s*\["
)
SCALAR_CONVERSION_RE = re.compile(
    r"\s*(?:await\s+)?(?:(?:int|long|short|byte|uint|ulong|ushort|double|float|"
    r"decimal|bool|Guid|DateTime|DateTimeOffset|TimeSpan|Int16|Int32|Int64)\s*\.\s*"
    r"Parse|Convert\s*\.\s*To(?:Int16|Int32|Int64|UInt16|UInt32|UInt64|Double|"
    r"Single|Decimal|Boolean|DateTime|Byte))\s*\("
)
ENCODER_CALL_RE = re.compile(
    r"\b(?:[\w.]*[Ee]ncoder\s*\.\s*(?:Default\s*\.\s*)?Encode|"
    r"(?:WebUtility|HttpUtility|AntiXssEncoder|Encoder)\s*\.\s*HtmlEncode|"
    r"[\w.]*[Ss]anitizer\s*\.\s*Sanitize)\s*\("
)
CONNECTION_FACTORY_RE = re.compile(
    r"\b(?:GetDbConnection|(?:Create|Get|Open)\w*Connection(?:Async)?)\s*\("
)
APP_ROOT_RE = re.compile(
    r"\bGetCurrentDirectory\s*\(|\bCurrentDirectory\b|\bContentRootPath\b"
    r"|\bBaseDirectory\b"
)

"""Maven, Gradle, Cargo, Composer, RubyGems, pub and NuGet lock inventories.

OSV is replaced by a local transport that reports one advisory for every
query, so the queried identities are the behaviour under test: Git, path,
SDK, private-registry and branch entries must never reach OSV.
"""

import json

import pytest

from skylos.core.gate_incomplete import incomplete_analysis_reasons
from skylos.core.gatekeeper import check_gate
from skylos.core.sca_baseline import dependency_fingerprints
from skylos.core.sca_coverage import valid_non_registry_sca_receipt
from skylos.reporting.listing import low_risk_context
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca
from skylos.rules.sca.advisory_metadata import extract_advisory_metadata


class _Response:
    status_code = 200
    headers = {}

    def __init__(self, payload):
        self.payload = payload

    def iter_content(self, chunk_size):
        yield json.dumps(self.payload).encode("utf-8")

    def close(self):
        pass


@pytest.fixture
def osv(monkeypatch):
    class Transport:
        def __init__(self):
            self.queries = []

        def post(self, url, *, json, **kwargs):
            start = len(self.queries)
            self.queries.extend(json["queries"])
            return _Response(
                {
                    "results": [
                        {"vulns": [{"id": f"OSV-TEST-{start + index}"}]}
                        for index in range(len(json["queries"]))
                    ]
                }
            )

        def get(self, url, **kwargs):
            index = int(url.rsplit("-", 1)[1])
            return _Response(
                {
                    "id": f"OSV-TEST-{index}",
                    "summary": "local test advisory",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [{"package": self.queries[index]["package"]}],
                }
            )

        def queried(self):
            return sorted(
                (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                for q in self.queries
            )

    transport = Transport()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


def _write(root, files):
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(  # skylos: ignore[SKY-D324] pytest fixture under tmp_path
            text, encoding="utf-8"
        )


def _not_checked(receipt):
    return sorted(
        (entry.get("name") or entry["package"], entry["reason"])
        for entry in receipt.get("lockfile_not_checked", [])
    )


def _dev_only(result):
    return sorted(
        finding["metadata"]["package_name"]
        for finding in result
        if finding.get("low_risk_context", {}).get("reason") == "dev-only-dependency"
    )


CARGO_LOCK = """version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "regex"
version = "1.5.4"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "smallvec"
version = "1.6.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "time"
version = "0.1.43"
source = "git+https://github.com/example/time?branch=main#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "tokio"
version = "1.8.0"
source = "registry+https://registry.example.com/index"
"""


def _composer_package(name, version, *, notification=True, dist="zip"):
    package = {
        "name": name,
        "version": version,
        "source": {"type": "git", "url": f"https://github.com/{name}.git"},
        "dist": {"type": dist, "url": f"https://example.test/{name}.zip"},
    }
    if notification is True:
        package["notification-url"] = "https://packagist.org/downloads/"
    elif notification:
        package["notification-url"] = notification
    return package


COMPOSER_LOCK = json.dumps(
    {
        "packages": [
            _composer_package("guzzlehttp/psr7", "1.8.3"),
            _composer_package("symfony/process", "dev-main"),
            _composer_package(
                "acme/local", "dev-main", notification=False, dist="path"
            ),
            _composer_package(
                "acme/private",
                "1.0.0",
                notification="https://repo.example.com/downloads/",
            ),
            _composer_package("acme/fork", "2.0.0", notification=False),
        ],
        "packages-dev": [_composer_package("symfony/http-kernel", "v4.4.0")],
    },
    indent=4,
)

GEMFILE_LOCK = """GIT
  remote: https://github.com/rails/rails.git
  revision: 0123456789abcdef0123456789abcdef01234567
  specs:
    actionpack (6.1.4)
      rack (~> 2.0)

PATH
  remote: engines/my_engine
  specs:
    my_engine (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.3)
      racc (~> 1.4)
    nokogiri (1.13.3-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.3)

GEM
  remote: https://gems.example.com/
  specs:
    concurrent-ruby (1.3.4)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  actionpack!
  nokogiri
  rack (= 2.2.3)

BUNDLED WITH
   2.4.10
"""

PUBSPEC_LOCK = """packages:
  dio:
    dependency: "direct dev"
    description:
      name: dio
      url: "https://pub.dev"
    source: hosted
    version: "4.0.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dartlang.org"
    source: hosted
    version: "0.13.2"
  local_utils:
    dependency: "direct main"
    description:
      path: "../local_utils"
      relative: true
    source: path
    version: "1.0.0"
  private_pkg:
    dependency: transitive
    description:
      name: private_pkg
      url: "https://pub.example.com"
    source: hosted
    version: "2.0.0"
  shelf:
    dependency: "direct main"
    description:
      path: "."
      ref: main
      resolved-ref: "0123456789abcdef0123456789abcdef01234567"
      url: "https://github.com/example/shelf.git"
    source: git
    version: "0.7.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"""

GRADLE_LOCKFILE = """# This is a Gradle generated file for dependency locking.
junit:junit:4.12=testCompileClasspath,testRuntimeClasspath
org.yaml:snakeyaml:1.30=compileClasspath,runtimeClasspath,testRuntimeClasspath
empty=annotationProcessor
"""

NUGET_LOCK = json.dumps(
    {
        "version": 1,
        "dependencies": {
            "net6.0": {
                "Newtonsoft.Json": {
                    "type": "Direct",
                    "requested": "[12.0.1, )",
                    "resolved": "12.0.1",
                },
                "System.Text.Encodings.Web": {
                    "type": "Transitive",
                    "resolved": "4.7.1",
                },
                "MyLib": {"type": "Project"},
            },
            "net8.0": {
                "Newtonsoft.Json": {
                    "type": "Direct",
                    "requested": "[13.0.3, )",
                    "resolved": "13.0.3",
                },
                "MyLib": {"type": "Project"},
            },
        },
    },
    indent=2,
)


@pytest.mark.parametrize(
    "files,queried,not_checked,dev_only,status",
    [
        (
            {
                "Cargo.lock": CARGO_LOCK,
                "vendor/x/Cargo.lock": CARGO_LOCK.replace("1.5.4", "1.5.3"),
            },
            [("crates.io", "regex", "1.5.4"), ("crates.io", "smallvec", "1.6.0")],
            [
                ("app", "local_package"),
                ("time", "non_registry_source"),
                ("tokio", "non_public_registry"),
            ],
            [],
            "complete_with_non_registry_sources",
        ),
        (
            {"composer.lock": COMPOSER_LOCK},
            [
                ("Packagist", "guzzlehttp/psr7", "1.8.3"),
                ("Packagist", "symfony/http-kernel", "4.4.0"),
            ],
            [
                ("acme/fork", "non_registry_source"),
                ("acme/local", "local_package"),
                ("acme/private", "non_public_registry"),
                ("symfony/process", "non_registry_source"),
            ],
            ["symfony/http-kernel"],
            "complete_with_non_registry_sources",
        ),
        (
            {"Gemfile.lock": GEMFILE_LOCK, "Gemfile": 'gem "rack"\n'},
            [("RubyGems", "nokogiri", "1.13.3"), ("RubyGems", "rack", "2.2.3")],
            [
                ("actionpack", "non_registry_source"),
                ("concurrent-ruby", "non_public_registry"),
                ("my_engine", "local_package"),
            ],
            [],
            "complete_with_non_registry_sources",
        ),
        (
            {"pubspec.lock": PUBSPEC_LOCK},
            [("Pub", "dio", "4.0.0"), ("Pub", "http", "0.13.2")],
            [
                ("flutter", "sdk_package"),
                ("local_utils", "local_package"),
                ("private_pkg", "non_public_registry"),
                ("shelf", "non_registry_source"),
            ],
            ["dio"],
            "complete_with_non_registry_sources",
        ),
        (
            {
                "gradle.lockfile": GRADLE_LOCKFILE,
                "build.gradle": "plugins { id 'java' }\n",
            },
            [("Maven", "junit:junit", "4.12"), ("Maven", "org.yaml:snakeyaml", "1.30")],
            [],
            ["junit:junit"],
            "complete",
        ),
        (
            {"packages.lock.json": NUGET_LOCK},
            [
                ("NuGet", "Newtonsoft.Json", "12.0.1"),
                ("NuGet", "Newtonsoft.Json", "13.0.3"),
                ("NuGet", "System.Text.Encodings.Web", "4.7.1"),
            ],
            [("MyLib", "local_package"), ("MyLib", "local_package")],
            [],
            "complete",
        ),
    ],
    ids=["cargo", "composer", "bundler", "pub", "gradle", "nuget"],
)
def test_lockfiles_query_only_public_registry_entries(
    tmp_path, osv, files, queried, not_checked, dev_only, status
):
    _write(tmp_path, files)

    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt

    assert osv.queried() == queried
    assert len(result) == len(queried)
    assert _not_checked(receipt) == not_checked
    assert _dev_only(result) == dev_only
    assert receipt["status"] == status
    assert receipt["parse_error_count"] == 0
    assert receipt["unsupported_inputs"] == []
    summary = {"analysis_summary": {"sca_coverage": receipt}}
    assert incomplete_analysis_reasons(summary) == []
    if status == "complete_with_non_registry_sources":
        assert valid_non_registry_sca_receipt(receipt)


def test_platform_gems_are_one_identity_with_every_lockfile_location(tmp_path, osv):
    _write(tmp_path, {"Gemfile.lock": GEMFILE_LOCK})

    result = sca.scan_dependencies(tmp_path)

    [nokogiri] = [f for f in result if f["metadata"]["package_name"] == "nokogiri"]
    assert nokogiri["metadata"]["package_version"] == "1.13.3"
    assert [o["line"] for o in nokogiri["metadata"]["dependency_occurrences"]] == [
        16,
        18,
    ]


PARENT_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <properties><spring.version>5.3.0</spring.version></properties>
  <dependencyManagement><dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies></dependencyManagement>
</project>
"""

CHILD_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>app</artifactId>
  <properties><snakeyaml.version>1.30</snakeyaml.version></properties>
  <dependencyManagement><dependencies>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-dependencies</artifactId>
      <version>3.3.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <!-- <dependency><groupId>x</groupId><artifactId>commented</artifactId><version>1</version></dependency> -->
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>${snakeyaml.version}</version>
    </dependency>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <version>[1.4,2.0)</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>${undefined.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
  <profiles><profile><id>extra</id><dependencies>
    <dependency><groupId>com.h2database</groupId><artifactId>h2</artifactId><version>1.4.200</version></dependency>
  </dependencies></profile></profiles>
  <build><plugins><plugin>
    <artifactId>maven-antrun-plugin</artifactId>
    <dependencies>
      <dependency><groupId>com.h2database</groupId><artifactId>h2</artifactId><version>1.4.200</version></dependency>
    </dependencies>
  </plugin></plugins></build>
</project>
"""


def test_pom_versions_follow_properties_parent_and_management_only(tmp_path, osv):
    _write(tmp_path, {"pom.xml": PARENT_POM, "app/pom.xml": CHILD_POM})

    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt

    assert osv.queried() == [
        ("Maven", "com.example:sibling", "1.0.0"),
        ("Maven", "commons-collections:commons-collections", "3.2.1"),
        ("Maven", "junit:junit", "4.12"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("Maven", "org.springframework:spring-core", "5.3.0"),
        ("Maven", "org.yaml:snakeyaml", "1.30"),
    ]
    assert receipt["unresolved_dependency_count"] == 4
    assert receipt["status"] == "complete_with_unresolved_versions"
    assert _dev_only(result) == ["junit:junit"]
    [log4j] = [
        f for f in result if f["metadata"]["package_name"].endswith("log4j-core")
    ]
    assert log4j["file"] == str(tmp_path / "app" / "pom.xml")
    assert log4j["line"] == 25


def test_pom_parent_outside_the_scan_root_is_not_read(tmp_path, osv):
    _write(tmp_path, {"pom.xml": PARENT_POM, "app/pom.xml": CHILD_POM})

    sca.scan_dependencies(tmp_path / "app")

    assert ("Maven", "org.springframework:spring-core", "5.3.0") not in osv.queried()


def _pom(coordinates, body="", parent=""):
    group, artifact, version = coordinates.split(":")
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        f"{parent}<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"<version>{version}</version>{body}</project>"
    )


def _dependency(coordinates, extra=""):
    group, artifact, version = coordinates.split(":")
    declared = ""
    if version:
        declared = f"<version>{version}</version>"
    return (
        f"<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"{declared}{extra}</dependency>"
    )


def _dependencies(*coordinates):
    return (
        "<dependencies>"
        + "".join(_dependency(item) for item in coordinates)
        + "</dependencies>"
    )


ACME_PARENT = (
    "<parent><groupId>com.acme</groupId><artifactId>acme-parent</artifactId>"
    "<version>1.0.0</version></parent>"
)
LOG4J = "org.apache.logging.log4j:log4j-core"
TEST_JAR = "<type>test-jar</type><classifier>tests</classifier>"


@pytest.mark.parametrize(
    "coordinates,version",
    [
        ("example:application:2.14.1", "${project.version}"),
        ("org.apache.logging.log4j:application:2.14.1", "2.14.1"),
    ],
    ids=["project-version", "shared-group"],
)
def test_standalone_pom_dependencies_are_queried_whatever_their_version_source(
    tmp_path, osv, coordinates, version
):
    _write(
        tmp_path,
        {"pom.xml": _pom(coordinates, _dependencies(f"{LOG4J}:{version}"))},
    )

    result = sca.scan_dependencies(tmp_path)

    assert osv.queried() == [("Maven", LOG4J, "2.14.1")]
    assert result.receipt["status"] == "complete"
    passed, _ = check_gate(
        {
            "dependency_vulnerabilities": list(result),
            "analysis_summary": {"sca_coverage": result.receipt},
        },
        {"gate": {"max_dependency_vulnerabilities": 0}},
    )
    assert passed is False


def test_only_poms_built_in_the_same_reactor_are_internal(tmp_path, osv):
    _write(
        tmp_path,
        {
            "pom.xml": _pom(
                "com.acme:acme-parent:1.0.0",
                "<packaging>pom</packaging><modules><module>core</module>"
                "<module>web</module><module>cli</module></modules>",
            ),
            "core/pom.xml": _pom("com.acme:acme-core:1.0.0", parent=ACME_PARENT),
            "web/pom.xml": _pom(
                "com.acme:acme-web:1.0.0",
                _dependencies(
                    "${project.groupId}:acme-core:${project.version}",
                    "${project.groupId}:acme-client:${project.version}",
                    f"{LOG4J}:2.14.1",
                ),
                ACME_PARENT,
            ),
            "cli/pom.xml": _pom(
                "com.acme:acme-cli:1.0.0",
                _dependencies("com.acme:acme-core:0.9.0"),
                ACME_PARENT,
            ),
            "web/src/test/resources/fake/pom.xml": _pom(f"{LOG4J}:2.14.1"),
        },
    )

    receipt = sca.scan_dependencies(tmp_path).receipt
    reactor_queries = osv.queried()
    osv.queries.clear()
    sca.scan_dependencies(tmp_path / "web")

    assert reactor_queries == [
        ("Maven", "com.acme:acme-client", "1.0.0"),
        ("Maven", "com.acme:acme-core", "0.9.0"),
        ("Maven", LOG4J, "2.14.1"),
    ]
    assert receipt["unresolved_dependency_count"] == 0
    assert osv.queried() == [
        ("Maven", "com.acme:acme-client", "1.0.0"),
        ("Maven", "com.acme:acme-core", "1.0.0"),
        ("Maven", LOG4J, "2.14.1"),
    ]


@pytest.mark.parametrize(
    "managed,declared,queried,unresolved",
    [
        (
            [_dependency(f"{LOG4J}:2.14.1"), _dependency(f"{LOG4J}:2.24.0", TEST_JAR)],
            [_dependency(f"{LOG4J}:")],
            [("Maven", LOG4J, "2.14.1")],
            0,
        ),
        (
            [_dependency(f"{LOG4J}:2.24.0", TEST_JAR)],
            [_dependency(f"{LOG4J}:"), _dependency(f"{LOG4J}:", TEST_JAR)],
            [("Maven", LOG4J, "2.24.0")],
            1,
        ),
    ],
    ids=["jar-and-test-jar", "test-jar-only"],
)
def test_managed_versions_match_type_and_classifier(
    tmp_path, osv, managed, declared, queried, unresolved
):
    body = (
        "<dependencyManagement><dependencies>"
        + "".join(managed)
        + "</dependencies></dependencyManagement><dependencies>"
        + "".join(declared)
        + "</dependencies>"
    )
    _write(tmp_path, {"pom.xml": _pom("example:application:1.0.0", body)})

    receipt = sca.scan_dependencies(tmp_path).receipt

    assert osv.queried() == queried
    assert receipt["unresolved_dependency_count"] == unresolved


PUB_LOCK_1_2_0 = (
    'packages:\n  http:\n    dependency: "direct overridden"\n    description:\n'
    '      name: http\n      url: "https://pub.dev"\n    source: hosted\n'
    '    version: "1.2.0"\n'
)


@pytest.mark.parametrize(
    "override,lock,queried,unresolved",
    [
        ("  http: 1.2.0\n", None, [("Pub", "http", "1.2.0")], 0),
        ("  http: 1.2.0\n", PUB_LOCK_1_2_0, [("Pub", "http", "1.2.0")], 0),
        ("  http:\n    path: ./private_http\n", None, [], 0),
        ("  http: ^1.2.0\n", None, [], 1),
        (
            "  path: 1.9.0\n",
            None,
            [("Pub", "http", "0.13.2"), ("Pub", "path", "1.9.0")],
            0,
        ),
    ],
    ids=["hosted", "hosted-with-lock", "path", "range", "other-package"],
)
def test_pub_dependency_overrides_replace_the_overridden_declaration(
    tmp_path, osv, override, lock, queried, unresolved
):
    files = {
        "pubspec.yaml": (
            "name: demo\ndependencies:\n  http: 0.13.2\n"
            f"dependency_overrides:\n{override}"
        )
    }
    if lock is not None:
        files["pubspec.lock"] = lock
    _write(tmp_path, files)

    receipt = sca.scan_dependencies(tmp_path).receipt

    assert osv.queried() == queried
    assert receipt["unresolved_dependency_count"] == unresolved


def test_manifest_exact_pins_are_queried_and_ranges_stay_unresolved(tmp_path, osv):
    _write(
        tmp_path,
        {
            "rust/Cargo.toml": (
                '[dependencies]\nserde = "=1.0.210"\nregex = "1.5"\n'
                'time = { git = "https://github.com/example/time" }\n'
                '[dev-dependencies]\nsmallvec = { version = "=1.6.0" }\n'
            ),
            "php/composer.json": json.dumps(
                {
                    "require": {
                        "php": "^8.1",
                        "ext-json": "*",
                        "monolog/monolog": "3.7.0",
                        "guzzlehttp/psr7": "^1.8",
                        "symfony/process": "dev-main",
                    },
                    "require-dev": {"symfony/http-kernel": "v4.4.0"},
                }
            ),
            "dart/pubspec.yaml": (
                "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n"
                "  http: 0.13.2\n  path: ^1.9.0\n  shelf:\n    git: https://example.test/shelf.git\n"
                "dev_dependencies:\n  dio: 4.0.0\n"
            ),
        },
    )

    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt

    assert osv.queried() == [
        ("Packagist", "monolog/monolog", "3.7.0"),
        ("Packagist", "symfony/http-kernel", "4.4.0"),
        ("Pub", "dio", "4.0.0"),
        ("Pub", "http", "0.13.2"),
        ("crates.io", "serde", "1.0.210"),
        ("crates.io", "smallvec", "1.6.0"),
    ]
    assert receipt["unresolved_dependency_count"] == 4
    assert receipt["lockfile_covered_unresolved_dependency_count"] == 0
    assert receipt["status"] == "complete_with_unresolved_versions"
    assert _dev_only(result) == ["dio", "smallvec", "symfony/http-kernel"]


def test_composer_short_pin_and_its_locked_release_are_one_identity(tmp_path, osv):
    _write(
        tmp_path,
        {
            "composer.lock": json.dumps(
                {"packages": [_composer_package("dompdf/dompdf", "v1.2.0")]}
            ),
            "composer.json": json.dumps({"require": {"dompdf/dompdf": "1.2"}}),
        },
    )

    [finding] = sca.scan_dependencies(tmp_path)

    assert osv.queried() == [("Packagist", "dompdf/dompdf", "1.2.0")]
    assert len(finding["metadata"]["dependency_occurrences"]) == 2


def test_workspace_lockfile_covers_only_workspace_members(tmp_path):
    _write(
        tmp_path,
        {
            "Cargo.toml": '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/old"]\n',
            "Cargo.lock": CARGO_LOCK,
            "crates/member/Cargo.toml": '[dependencies]\nregex = "1.5"\n',
            "crates/old/Cargo.toml": '[dependencies]\nregex = "1.5"\n',
            "tools/Cargo.toml": '[dependencies]\nregex = "1.5"\n',
            "pubspec.yaml": "name: root\nworkspace:\n  - pkgs/app\n",
            "pubspec.lock": PUBSPEC_LOCK,
            "pkgs/app/pubspec.yaml": "name: app\nresolution: workspace\ndependencies:\n  http: ^0.13.0\n",
            "pkgs/solo/pubspec.yaml": "name: solo\ndependencies:\n  http: ^0.13.0\n",
        },
    )

    inventory = sca.collect_dependencies(tmp_path)

    covered = {
        directory
        for directory, _ in inventory.lockfile_projects
        if directory != str(tmp_path)
    }
    assert covered == {
        str(tmp_path / "crates" / "member"),
        str(tmp_path / "pkgs" / "app"),
    }
    assert inventory.receipt["unresolved_dependency_count"] == 5
    assert inventory.receipt["lockfile_covered_unresolved_dependency_count"] == 2


def test_nuget_lockfile_covers_minimum_csproj_versions(tmp_path, osv):
    _write(
        tmp_path,
        {
            "packages.lock.json": NUGET_LOCK,
            "App.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
                "</ItemGroup></Project>"
            ),
        },
    )

    receipt = sca.scan_dependencies(tmp_path).receipt

    assert ("NuGet", "Newtonsoft.Json", "12.0.1") in osv.queried()
    assert receipt["nuget_unpinned_count"] == 1
    assert receipt["complete"] is True


@pytest.mark.parametrize(
    "filename,text",
    [
        (
            "pom.xml",
            '<!DOCTYPE project [<!ENTITY v "2.14.1">]><project><dependencies>'
            "<dependency><groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId><version>&v;</version>"
            "</dependency></dependencies></project>",
        ),
        ("Cargo.lock", 'version = 3\n[[package]\nname = "smallvec'),
        (
            "Cargo.lock",
            'version = 9\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\n',
        ),
        ("composer.lock", '{"packages": [{"name": "guzzlehttp/psr7"'),
        ("composer.lock", "{}"),
        (
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack 2.2.3\n",
        ),
        ("Gemfile.lock", "<<<<<<< HEAD\nGEM\n"),
        ("gradle.lockfile", "org.yaml:snakeyaml=compileClasspath\n"),
        ("pubspec.lock", "packages:\n  - http\n"),
        ("pubspec.lock", "packages:\n  http: &a {}\n  dio: *a\n"),
        ("packages.lock.json", '{"version": 99, "dependencies": {}}'),
    ],
)
def test_malformed_dependency_files_fail_closed_and_are_named(
    tmp_path, osv, filename, text
):
    _write(tmp_path, {filename: text})

    result = sca.scan_dependencies(tmp_path)
    receipt = result.receipt

    assert list(result) == []
    assert osv.queries == []
    assert receipt["status"] == "incomplete"
    assert receipt["parse_error_count"] == 1
    assert [entry["file"] for entry in receipt["parse_errors"]] == [
        str(tmp_path / filename)
    ]
    summary = {"analysis_summary": {"sca_coverage": receipt}}
    assert incomplete_analysis_reasons(summary)


def test_oversized_lockfile_is_not_parsed(tmp_path, osv, monkeypatch):
    monkeypatch.setattr(sca, "MAX_MANIFEST_BYTES", 200)
    _write(tmp_path, {"Cargo.lock": CARGO_LOCK})

    receipt = sca.scan_dependencies(tmp_path).receipt

    assert osv.queries == []
    assert receipt["parse_errors"] == [
        {
            "file": str(tmp_path / "Cargo.lock"),
            "reason": "unreadable_oversized_or_not_utf8",
        }
    ]


@pytest.mark.parametrize(
    "ecosystem,name,version",
    [
        ("Maven", "org.yaml:snakeyaml", "1.30"),
        ("crates.io", "regex", "1.5.4"),
        ("Packagist", "guzzlehttp/psr7", "1.8.3"),
        ("RubyGems", "rack", "2.2.3"),
        ("Pub", "http", "0.13.2"),
        ("NuGet", "Newtonsoft.Json", "12.0.1"),
    ],
)
def test_new_ecosystems_have_baseline_identities_and_purls(
    tmp_path, ecosystem, name, version
):
    dependency = {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "file": str(tmp_path / "lock"),
        "line": 3,
        "lockfile_version": 1,
        "exact": True,
        "conditional": False,
        "version_override": False,
        "reference_mutated": False,
    }
    advisory = {
        "id": "GHSA-test-baseline",
        "summary": "test",
        "affected": [{"package": {"ecosystem": ecosystem, "name": name.upper()}}],
    }
    vuln = extract_advisory_metadata(advisory, dependency)
    vuln["advisory_status"] = "complete"
    finding = sca._make_finding(dependency, vuln)
    renamed = sca._make_finding({**dependency, "name": name.upper()}, vuln)

    identity = dependency_fingerprints(finding, tmp_path)
    assert identity
    case_insensitive = ecosystem in {"NuGet", "Packagist"}
    assert (dependency_fingerprints(renamed, tmp_path) == identity) is case_insensitive
    assert (sca.advisory_matches_dependency(advisory, dependency)) is case_insensitive

    inventory = sca.DependencyInventory(
        sca._unique_dependency_inventory([dependency]),
        receipt={"status": "complete", "complete": True},
    )
    bom = cyclonedx_bom(inventory, tmp_path)
    assert bom.receipt["invalid_identity_count"] == 0
    [component] = bom["components"]
    assert component["purl"].startswith(
        {
            "Maven": "pkg:maven/org.yaml/snakeyaml@1.30",
            "crates.io": "pkg:cargo/regex@1.5.4",
            "Packagist": "pkg:composer/guzzlehttp/psr7@1.8.3",
            "RubyGems": "pkg:gem/rack@2.2.3",
            "Pub": "pkg:pub/http@0.13.2",
            "NuGet": "pkg:nuget/newtonsoft.json@12.0.1",
        }[ecosystem]
    )


def _repeated_lockfiles(root, kind, projects, names):
    for index in range(projects):
        if kind == "npm":
            packages = {"": {"name": "app"}}
            packages.update({f"node_modules/{n}": {"version": "1.0.0"} for n in names})
            files = {
                f"p{index}/package-lock.json": json.dumps(
                    {"lockfileVersion": 3, "packages": packages}
                )
            }
        else:
            files = {
                f"p{index}/Cargo.lock": "version = 3\n"
                + "".join(
                    f'[[package]]\nname = "{n}"\nversion = "1.0.0"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    for n in names
                )
            }
        _write(root, files)


@pytest.mark.parametrize("kind", ["npm", "cargo"])
def test_entries_repeated_across_lockfiles_count_once_against_the_unique_limit(
    tmp_path, osv, monkeypatch, kind
):
    _repeated_lockfiles(tmp_path, kind, 3, ["alpha", "beta"])
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 2)

    result = sca.scan_dependencies(tmp_path)

    assert "limit_reasons" not in result.receipt
    assert result.receipt["complete"] is True
    assert len(osv.queried()) == 2
    assert {len(f["metadata"]["dependency_occurrences"]) for f in result} == {3}


@pytest.mark.parametrize("kind", ["npm", "cargo"])
def test_more_unique_dependencies_than_the_limit_still_fail_closed(
    tmp_path, osv, monkeypatch, kind
):
    _repeated_lockfiles(tmp_path, kind, 1, ["alpha", "beta", "gamma"])
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 2)

    result = sca.scan_dependencies(tmp_path)

    assert list(result) == []
    assert osv.queries == []
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["limit_reasons"] == ["dependency_limit_exceeded"]
    summary = {"analysis_summary": {"sca_coverage": result.receipt}}
    [reason] = incomplete_analysis_reasons(summary)
    assert "more than 2 unique dependencies" in str(reason)


@pytest.mark.parametrize("kind", ["npm", "cargo"])
def test_entry_ceiling_bounds_parsing_of_repeated_lockfiles(
    tmp_path, osv, monkeypatch, kind
):
    _repeated_lockfiles(tmp_path, kind, 4, ["alpha", "beta"])
    monkeypatch.setattr(sca, "MAX_DEPENDENCY_ENTRIES", 7)

    result = sca.scan_dependencies(tmp_path)

    assert osv.queries == []
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["limit_reasons"] == ["dependency_entry_limit_exceeded"]
    summary = {"analysis_summary": {"sca_coverage": result.receipt}}
    [reason] = incomplete_analysis_reasons(summary)
    assert "more than 7 entries" in str(reason)


@pytest.mark.parametrize(
    "informational,demoted",
    [("unmaintained", True), ("notice", True), ("unsound", False), (None, False)],
)
def test_rustsec_informational_notices_are_reported_but_not_listed_as_vulnerabilities(
    informational, demoted
):
    dependency = {
        "name": "paste",
        "version": "1.0.15",
        "ecosystem": "crates.io",
        "file": "Cargo.lock",
        "line": 3,
    }
    affected = {"package": {"ecosystem": "crates.io", "name": "paste"}}
    if informational:
        affected["database_specific"] = {"informational": informational}
    advisory = {"id": "RUSTSEC-2024-0436", "summary": "test", "affected": [affected]}

    finding = sca._make_finding(
        dependency, extract_advisory_metadata(advisory, dependency)
    )

    assert finding["rule_id"] == "SKY-SCA-RUSTSEC-2024-0436"
    assert finding["metadata"].get("advisory_informational") == informational
    assert (low_risk_context(finding) is not None) is demoted
    forged = {**finding, "rule_id": "SKY-D211"}
    assert low_risk_context(forged) is None


@pytest.mark.parametrize(
    "ecosystem,range_type,version,events,fixed",
    [
        (
            "crates.io",
            "SEMVER",
            "1.5.4",
            [{"introduced": "0"}, {"fixed": "1.5.5"}],
            "1.5.5",
        ),
        ("Maven", "ECOSYSTEM", "1.30", [{"introduced": "0"}, {"fixed": "2.0"}], "2.0"),
        (
            "RubyGems",
            "ECOSYSTEM",
            "2.2.3",
            [{"introduced": "0.4"}, {"fixed": "2.2.8.1"}],
            "2.2.8.1",
        ),
        ("Maven", "ECOSYSTEM", "2.0", [{"introduced": "0"}, {"fixed": "2.0.0"}], None),
        (
            "crates.io",
            "ECOSYSTEM",
            "1.5.4",
            [{"introduced": "0"}, {"fixed": "1.5.5"}],
            None,
        ),
    ],
)
def test_upgrade_hint_uses_each_ecosystems_version_order(
    ecosystem, range_type, version, events, fixed
):
    advisory = {
        "id": "GHSA-test-fix",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": "pkg"},
                "ranges": [{"type": range_type, "events": events}],
            }
        ],
    }
    dependency = {"ecosystem": ecosystem, "name": "pkg", "version": version}

    assert extract_advisory_metadata(advisory, dependency)["fixed_version"] == fixed

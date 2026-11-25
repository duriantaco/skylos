"""Generate CycloneDX inventories from built Skylos distributions without installing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import quote

if __package__:
    from .build_go_wheels import ENGINE_ARCNAME
else:
    from build_go_wheels import ENGINE_ARCNAME


SCHEMA = "https://cyclonedx.org/schema/bom-1.6.schema.json"
ENGINE_NAMES = {ENGINE_ARCNAME, ENGINE_ARCNAME + ".exe"}
NPM_MANIFEST = re.compile(r"node_modules/(?:@[^/]+/)?[^/]+/package\.json$")


def component(ecosystem, name, version=None, *, kind="library"):
    ref = f"pkg:{ecosystem}/{quote(name, safe='/')}"
    if version:
        ref += "@" + quote(version, safe="")
    item = {"type": kind, "name": name, "purl": ref, "bom-ref": ref}
    if version:
        item["version"] = version
    return item


def digest(value):
    return {"alg": "SHA-256", "content": value}


def python_inventory(metadata):
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    message = BytesParser(policy=policy.default).parsebytes(metadata)
    root = component(
        "pypi",
        canonicalize_name(message["Name"]),
        message["Version"],
        kind="application",
    )
    declarations = {}
    for header in message.get_all("Requires-Dist", []):
        requirement = Requirement(str(header))
        name = canonicalize_name(requirement.name)
        declarations.setdefault(name, set()).add(str(requirement))
    dependencies = []
    for name, requirements in sorted(declarations.items()):
        dependency = component("pypi", name)
        dependency["properties"] = [
            {"name": "skylos:python:requires-dist", "value": requirement}
            for requirement in sorted(requirements)
        ]
        dependencies.append(dependency)
    return root, dependencies


def bundled_go(archive, member, release_version):
    data = archive.read(member)
    # Read Go's embedded metadata. The wheel's binary is never executed.
    with tempfile.TemporaryDirectory(prefix="skylos-sbom-") as scratch:
        binary = Path(scratch) / Path(member).name
        binary.write_bytes(data)
        result = subprocess.run(
            ["go", "version", "-m", "-json", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        )
    build = json.loads(result.stdout)
    engine = component("generic", "skylos-go", release_version, kind="application")
    engine["hashes"] = [digest(hashlib.sha256(data).hexdigest())]
    engine["properties"] = [{"name": "skylos:artifact:member", "value": member}]
    stdlib = component("golang", "stdlib", build["GoVersion"].removeprefix("go"))
    modules = [stdlib]
    for dep in build.get("Deps") or []:
        linked = dep.get("Replace") or dep
        modules.append(
            component("golang", linked["Path"], linked.get("Version") or None)
        )
    return engine, modules


def wheel_inventory(path):
    with zipfile.ZipFile(path) as archive:
        (metadata,) = [
            member
            for member in archive.namelist()
            if member.endswith(".dist-info/METADATA")
        ]
        root, dependencies = python_inventory(archive.read(metadata))
        native = ENGINE_NAMES.intersection(archive.namelist())
        if not native:
            return root, dependencies, []
        (member,) = native
        engine, modules = bundled_go(archive, member, root["version"])
    dependencies.append(engine)
    return root, dependencies, [(engine, modules)]


def sdist_inventory(path):
    with tarfile.open(path) as archive:
        (metadata,) = [
            member
            for member in archive
            if member.name.count("/") == 1 and member.name.endswith("/PKG-INFO")
        ]
        stream = archive.extractfile(metadata)
        if stream is None:
            raise ValueError(f"{path.name}: PKG-INFO is not a regular file")
        with stream:
            root, dependencies = python_inventory(stream.read())
    return root, dependencies, []


def vsix_inventory(path):
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("extension/package.json"))
        qualified_name = f"{manifest['publisher']}/{manifest['name']}"
        root = component(
            "generic", qualified_name, manifest["version"], kind="application"
        )
        direct = set(manifest.get("dependencies", ())) | set(
            manifest.get("optionalDependencies", ())
        )
        bundled = []
        for member in sorted(archive.namelist()):
            if not member.startswith(
                "extension/node_modules/"
            ) or not NPM_MANIFEST.search(member):
                continue
            package = json.loads(archive.read(member))
            bundled.append(component("npm", package["name"], package["version"]))
    return root, [item for item in bundled if item["name"] in direct], [(root, bundled)]


def make_sbom(path):
    inventory = {
        ".whl": wheel_inventory,
        ".tar.gz": sdist_inventory,
        ".vsix": vsix_inventory,
    }
    suffix = ".tar.gz" if path.name.endswith(".tar.gz") else path.suffix
    root, direct, nested = inventory[suffix](path)
    with path.open("rb") as stream:
        root["hashes"] = [digest(hashlib.file_digest(stream, "sha256").hexdigest())]
    root["properties"] = [{"name": "skylos:artifact:filename", "value": path.name}]
    if suffix == ".vsix":
        root["properties"].append(
            {
                "name": "skylos:inventory:scope",
                "value": "Bundled extension packages. VS Code and Skylos CLI are installed separately.",
            }
        )
    else:
        root["properties"].append(
            {
                "name": "skylos:inventory:scope",
                "value": "Python version ranges and markers come from release metadata. The installer resolves transitive versions in the target environment.",
            }
        )
    items = {item["bom-ref"]: item for item in direct}
    relationships = [{"ref": root["bom-ref"], "dependsOn": sorted(items)}]
    for owner, children in nested:
        if owner is not root:
            relationships.append(
                {
                    "ref": owner["bom-ref"],
                    "dependsOn": sorted({item["bom-ref"] for item in children}),
                }
            )
        items.update((item["bom-ref"], item) for item in children)
    return {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": root},
        "components": [items[ref] for ref in sorted(items)],
        "dependencies": relationships,
        "compositions": [{"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path in args.artifacts:
        target = args.out_dir / f"{path.name}.cdx.json"
        target.write_text(
            json.dumps(make_sbom(path), indent=2) + "\n", encoding="utf-8"
        )
        print(target)


if __name__ == "__main__":
    main()

import tarfile
from pathlib import Path

from flask import Flask, request


app = Flask(__name__)
EXTRACT_ROOT = Path("/srv/bundles")


def _target_within_root(root: Path, member_name: str) -> bool:
    target = (root / member_name).resolve()
    return target == root or str(target).startswith(f"{root}/")


@app.post("/extract-bundle")
def extract_bundle():
    upload = request.files["bundle"]
    archive_path = EXTRACT_ROOT / upload.filename
    upload.save(archive_path)
    with tarfile.open(archive_path) as bundle:
        bundle.extractall(EXTRACT_ROOT)
    return "ok"


@app.post("/extract-bundle-safe")
def extract_bundle_safe():
    upload = request.files["bundle"]
    archive_path = EXTRACT_ROOT / upload.filename
    upload.save(archive_path)
    root = EXTRACT_ROOT.resolve()
    with tarfile.open(archive_path) as bundle:
        safe_members = [
            member
            for member in bundle.getmembers()
            if _target_within_root(root, member.name)
        ]
        bundle.extractall(root, members=safe_members)
    return "ok"

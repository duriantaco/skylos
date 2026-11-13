"""Shrink raw capture PNGs into docs/handbook/img/cloud/.

Reads $HANDBOOK_CLOUD_WORK/raw/*.png (2x captures), trims the empty page
background around the panel, scales every image by the same factor (1.2
pixels per CSS pixel, so text prints at one size; the builder's
SHOT_MM_PER_PIXEL assumes this), reduces it to a 128-colour palette and
writes an optimised PNG. Only images a chapter refers to are written.
"""

from __future__ import annotations

import os
import re
import sys
from collections import Counter
from pathlib import Path

from PIL import Image, ImageChops

SCALE = 0.6
COLOURS = 128
MARGIN = 28
HERE = Path(__file__).resolve().parent
OUT_DIR = HERE.parent.parent / "img" / "cloud"


def edge_colour(image: Image.Image) -> tuple[int, int, int]:
    width, height = image.size
    pixels = []
    for x in range(0, width, 4):
        pixels.append(image.getpixel((x, 0)))
        pixels.append(image.getpixel((x, height - 1)))
    for y in range(0, height, 4):
        pixels.append(image.getpixel((0, y)))
        pixels.append(image.getpixel((width - 1, y)))
    return Counter(pixels).most_common(1)[0][0]


def trim(image: Image.Image) -> Image.Image:
    background = Image.new("RGB", image.size, edge_colour(image))
    difference = ImageChops.difference(image, background).convert("L")
    box = difference.point(lambda value: 255 if value > 10 else 0).getbbox()
    if not box:
        return image
    left = max(0, box[0] - MARGIN)
    top = max(0, box[1] - MARGIN)
    right = min(image.width, box[2] + MARGIN)
    bottom = min(image.height, box[3] + MARGIN)
    return image.crop((left, top, right, bottom))


def shrink(source: Path, target: Path) -> int:
    image = trim(Image.open(source).convert("RGB"))
    size = (round(image.width * SCALE), round(image.height * SCALE))
    image = image.resize(size, Image.LANCZOS)
    reduced = image.quantize(colors=COLOURS, method=Image.MEDIANCUT, dither=Image.NONE)
    reduced.save(target, optimize=True)
    return target.stat().st_size


def referenced() -> set[str]:
    names = set()
    for chapter in HERE.parent.glob("*.md"):
        names.update(
            re.findall(r"\(img/cloud/([^)]+)\)", chapter.read_text(encoding="utf-8"))
        )
    return names


def main() -> int:
    work = os.environ.get("HANDBOOK_CLOUD_WORK")
    if not work:
        print("set HANDBOOK_CLOUD_WORK", file=sys.stderr)
        return 2
    raw = Path(work) / "raw"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    wanted = set(sys.argv[1:])
    used = referenced()
    total = 0
    count = 0
    for source in sorted(raw.glob("*.png")):
        if source.name.startswith(("crawl", "x-")):
            continue
        if wanted and source.stem not in wanted:
            continue
        if source.name not in used:
            continue
        size = shrink(source, OUT_DIR / source.name)
        total += size
        count += 1
        print(f"{source.name}: {size // 1024} KB")
    print(f"{count} images, {total // 1024} KB")
    missing = sorted(used - {path.name for path in OUT_DIR.glob("*.png")})
    if missing:
        print(f"referenced but not captured: {missing}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

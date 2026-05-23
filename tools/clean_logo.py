"""Strip the white background from ``assets/anglerfish.png`` and
recolour the white interior details to match the bioluminescent palette.

Floods the outer-white region from each corner with a sentinel colour,
then builds an alpha mask where flooded pixels are transparent and
everything else is opaque. White pixels *inside* the silhouette (eye,
teeth-gap detailing) are not connected to the corners, so they survive
the flood — and then get recoloured to ``--bioluminescence-soft`` so
the artwork is monochromatic-cyan instead of mixed cyan+white.

Overwrites the source file in place.

    python tools/clean_logo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
LOGO = ROOT / "assets" / "anglerfish.png"

# Sentinel RGB that won't appear in the artwork (deep magenta).
SENTINEL = (255, 0, 255)
# Per-channel tolerance for the corner flood. Generous enough to swallow
# JPEG-style off-white edge pixels (252-254), tight enough to stop at
# the cyan glow's outer halo.
FLOOD_THRESH = 12
# --bioluminescence-soft from the dashboard palette. White interior
# details (eye, teeth-gaps) are repainted in this colour so the artwork
# is monochromatic-cyan.
BIO_SOFT = (103, 232, 249)


def strip_white_background(img: Image.Image) -> Image.Image:
    """Two-pass background removal.

    Pass 1 — flood from each corner with a tight threshold. This catches
    the pure white outer region without bleeding into the cyan glow.

    Pass 2 — iteratively dilate the background into adjacent pixels that
    are *bright + low-saturation*. This swallows the JPEG-style gradient
    noise the flood couldn't traverse, but only where it's already
    touching the established background — so the white eye and teeth-gap
    pixels *inside* the silhouette stay opaque.
    """
    rgb = img.convert("RGB").copy()
    w, h = rgb.size
    for corner in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
        ImageDraw.floodfill(rgb, corner, SENTINEL, thresh=FLOOD_THRESH)
    src_rgb = img.convert("RGB")
    src_p = src_rgb.load()
    rgbp = rgb.load()
    assert src_p is not None and rgbp is not None

    def is_noise(x: int, y: int) -> bool:
        r, g, b = src_p[x, y]
        return min(r, g, b) > 190 and (max(r, g, b) - min(r, g, b)) < 12

    changed = True
    while changed:
        changed = False
        for y in range(h):
            for x in range(w):
                if rgbp[x, y] == SENTINEL or not is_noise(x, y):
                    continue
                for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1)):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < w and 0 <= ny < h and rgbp[nx, ny] == SENTINEL:
                        rgbp[x, y] = SENTINEL
                        changed = True
                        break

    alpha = Image.new("L", rgb.size)
    ap = alpha.load()
    assert ap is not None
    for y in range(h):
        for x in range(w):
            ap[x, y] = 0 if rgbp[x, y] == SENTINEL else 255
    result = img.convert("RGBA").copy()
    result.putalpha(alpha)
    # Recolour interior white details (eye + teeth-gaps) to the cyan
    # palette colour so the artwork is monochromatic.
    rp = result.load()
    assert rp is not None
    for y in range(h):
        for x in range(w):
            if ap[x, y] == 0:
                continue
            r, g, b = src_p[x, y]
            if min(r, g, b) > 200 and (max(r, g, b) - min(r, g, b)) < 12:
                rp[x, y] = (*BIO_SOFT, 255)
    return result


def main() -> int:
    if not LOGO.exists():
        print(f"missing logo: {LOGO}", file=sys.stderr)
        return 1
    src = Image.open(LOGO)
    print(f"cleaning {LOGO.relative_to(ROOT)} ({src.size[0]}x{src.size[1]})")
    out = strip_white_background(src)
    out.save(LOGO, format="PNG", optimize=True)
    print(f"wrote {LOGO.relative_to(ROOT)} ({LOGO.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

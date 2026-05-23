"""Generate the README banner from the bioluminescent dashboard palette.

Output: ``assets/anglerfish-banner.png`` — static PNG (1280x320) with
the cleaned fish sigil centred on the deep-sea radial gradient that
matches the dashboard ``body`` + ``.lure`` background in
``src/anglerfish/dashboard/static/style.css``.

Source: ``assets/anglerfish.png`` (already background-stripped by
``tools/clean_logo.py``).

    python tools/generate_banner.py
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SIGIL_SRC = ROOT / "assets" / "anglerfish.png"
BANNER_OUT = ROOT / "assets" / "anglerfish-banner.png"

WIDTH, HEIGHT = 1280, 320

# Palette (from dashboard/static/style.css :root).
ABYSS = (2, 6, 15, 255)
ABYSS_2 = (5, 11, 29, 255)
ABYSS_3 = (10, 21, 48, 255)
BORDER = (34, 211, 238, 46)       # rgba(34,211,238,0.18)

# Sigil height in banner pixels — leaves ~24px breathing room top/bottom.
SIGIL_H = 272


def make_background() -> Image.Image:
    """Reproduce the body radial gradient + .lure top linear overlay."""
    bg = Image.new("RGBA", (WIDTH, HEIGHT), ABYSS)
    px = bg.load()
    assert px is not None
    cx, cy = WIDTH / 2, 0
    rx, ry = WIDTH * 0.65, HEIGHT * 1.2
    for y in range(HEIGHT):
        for x in range(WIDTH):
            dx = (x - cx) / rx
            dy = (y - cy) / ry
            t = min(1.0, math.sqrt(dx * dx + dy * dy) / 0.6)
            r = round(ABYSS_2[0] + (ABYSS[0] - ABYSS_2[0]) * t)
            g = round(ABYSS_2[1] + (ABYSS[1] - ABYSS_2[1]) * t)
            b = round(ABYSS_2[2] + (ABYSS[2] - ABYSS_2[2]) * t)
            px[x, y] = (r, g, b, 255)
    overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    olpx = overlay.load()
    assert olpx is not None
    for y in range(HEIGHT):
        a = max(0, round(255 * (1 - y / HEIGHT)))
        for x in range(WIDTH):
            olpx[x, y] = (*ABYSS_3[:3], a)
    bg.alpha_composite(overlay)
    ImageDraw.Draw(bg).line([(0, HEIGHT - 1), (WIDTH, HEIGHT - 1)], fill=BORDER, width=1)
    return bg


def load_sigil() -> Image.Image:
    """Open the source, crop to its alpha bounding box, and scale to SIGIL_H."""
    sigil = Image.open(SIGIL_SRC).convert("RGBA")
    bbox = sigil.getbbox()
    if bbox is None:
        raise RuntimeError(f"{SIGIL_SRC} has no opaque pixels")
    sigil = sigil.crop(bbox)
    ratio = SIGIL_H / sigil.height
    new_w = round(sigil.width * ratio)
    return sigil.resize((new_w, SIGIL_H), Image.LANCZOS)


def compose_banner() -> Image.Image:
    base = make_background()
    sigil = load_sigil()
    sigil_x = (WIDTH - sigil.width) // 2
    sigil_y = (HEIGHT - SIGIL_H) // 2
    base.alpha_composite(sigil, (sigil_x, sigil_y))
    return base


def main() -> int:
    if not SIGIL_SRC.exists():
        print(f"missing sigil: {SIGIL_SRC}", file=sys.stderr)
        return 1
    print("rendering banner")
    banner = compose_banner()
    BANNER_OUT.parent.mkdir(parents=True, exist_ok=True)
    banner.save(BANNER_OUT, format="PNG", optimize=True)
    size_kb = BANNER_OUT.stat().st_size / 1024
    print(f"wrote {BANNER_OUT.relative_to(ROOT)} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

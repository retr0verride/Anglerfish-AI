"""Generate the README banner from the bioluminescent dashboard palette.

Output: ``assets/anglerfish-banner.png`` — static PNG (1280x320) with
the cleaned fish sigil on the left and a glowing 'ANGLERFISH AI' title
+ tagline to its right, all on the deep-sea radial gradient that
mirrors the dashboard ``body`` + ``.lure`` background in
``src/anglerfish/dashboard/static/style.css``.

Source: ``assets/anglerfish.png`` (already background-stripped and
recoloured by ``tools/clean_logo.py``).

    python tools/generate_banner.py
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SIGIL_SRC = ROOT / "assets" / "anglerfish.png"
BANNER_OUT = ROOT / "assets" / "anglerfish-banner.png"

WIDTH, HEIGHT = 1280, 320

# Palette (from dashboard/static/style.css :root).
ABYSS = (2, 6, 15, 255)
ABYSS_2 = (5, 11, 29, 255)
ABYSS_3 = (10, 21, 48, 255)
BIO = (34, 211, 238)              # --bioluminescence
BIO_SOFT = (103, 232, 249)        # --bioluminescence-soft
TEXT_DIM = (148, 168, 192)        # --text-dim
BORDER = (34, 211, 238, 46)       # rgba(34,211,238,0.18)

# Layout.
PAD = 64
SIGIL_H = 140
GAP = 56

# Fonts — Segoe UI ships with Windows and is the closest match to the
# Inter stack the dashboard uses.
WIN_FONTS = Path("C:/Windows/Fonts")
FONT_TITLE = WIN_FONTS / "segoeuib.ttf"   # Segoe UI Bold
FONT_SUB = WIN_FONTS / "segoeui.ttf"      # Segoe UI Regular

TITLE_SIZE = 88
SUB_SIZE = 28
TITLE_TRACK = 14  # ~0.16em letter-spacing at 88px

TITLE_TEXT = "ANGLERFISH AI"
SUB_TEXT = "Deep-sea SSH honeypot · AI-powered threat intelligence"


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
    """Open the source, crop to its alpha bounding box, scale to SIGIL_H."""
    sigil = Image.open(SIGIL_SRC).convert("RGBA")
    bbox = sigil.getbbox()
    if bbox is None:
        raise RuntimeError(f"{SIGIL_SRC} has no opaque pixels")
    sigil = sigil.crop(bbox)
    ratio = SIGIL_H / sigil.height
    return sigil.resize((round(sigil.width * ratio), SIGIL_H), Image.LANCZOS)


def tracked_width(text: str, font: ImageFont.FreeTypeFont, track: int) -> int:
    if not text:
        return 0
    total = 0
    for ch in text:
        bbox = font.getbbox(ch)
        total += (bbox[2] - bbox[0]) + track
    return total - track


def draw_tracked(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int] | tuple[int, int, int, int],
    track: int,
) -> None:
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        bbox = font.getbbox(ch)
        x += (bbox[2] - bbox[0]) + track


def render_title(text: str, font: ImageFont.FreeTypeFont) -> Image.Image:
    """Title with a soft cyan glow underneath, matching CSS text-shadow."""
    text_w = tracked_width(text, font, TITLE_TRACK)
    pad = 40
    w = text_w + pad * 2
    h = TITLE_SIZE * 2
    glow_layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw_tracked(ImageDraw.Draw(glow_layer), (pad, h // 4), text, font, (*BIO, 200), TITLE_TRACK)
    glow = glow_layer.filter(ImageFilter.GaussianBlur(6))
    fg = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw_tracked(ImageDraw.Draw(fg), (pad, h // 4), text, font, (*BIO_SOFT, 255), TITLE_TRACK)
    glow.alpha_composite(fg)
    return glow


def compose_banner() -> Image.Image:
    base = make_background()
    sigil = load_sigil()
    sigil_x = PAD
    sigil_y = (HEIGHT - SIGIL_H) // 2
    base.alpha_composite(sigil, (sigil_x, sigil_y))

    title_font = ImageFont.truetype(str(FONT_TITLE), TITLE_SIZE)
    sub_font = ImageFont.truetype(str(FONT_SUB), SUB_SIZE)
    title_img = render_title(TITLE_TEXT, title_font)

    text_x = sigil_x + sigil.width + GAP
    # Vertically centre the title+subtitle block as a unit.
    sub_gap = 18
    block_h = TITLE_SIZE + sub_gap + SUB_SIZE
    block_y = (HEIGHT - block_h) // 2
    # title_img has the glyphs at h//4 with TITLE_SIZE*2 canvas, so the
    # glyph top sits at TITLE_SIZE//2 from the layer's top.
    base.alpha_composite(title_img, (text_x - 40, block_y - TITLE_SIZE // 2))

    sub_y = block_y + TITLE_SIZE + sub_gap
    ImageDraw.Draw(base).text((text_x, sub_y), SUB_TEXT, font=sub_font, fill=TEXT_DIM)
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

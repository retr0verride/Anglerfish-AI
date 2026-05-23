"""Generate the README banner from the bioluminescent dashboard palette.

Output: ``assets/anglerfish-banner.png`` — static PNG (1280x320) whose
layout, palette and sigil halo match the dashboard ``.lure`` header in
``src/anglerfish/dashboard/static/style.css``.

The source artwork surrounds the bulb with a dotted cyan/dark mesh that
reads as a checkerboard at any zoom; we wipe that ring before
compositing while preserving the clean cyan bulb disc itself.

Re-run after editing dashboard styles or bumping the version so the
README banner stays in sync.

    python tools/generate_banner.py
"""

from __future__ import annotations

import math
import sys
import tomllib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SIGIL_SRC = ROOT / "assets" / "anglerfish-logo.png"
BANNER_OUT = ROOT / "assets" / "anglerfish-banner.png"

WIDTH, HEIGHT = 1280, 320

# Palette (from dashboard/static/style.css :root)
ABYSS = (2, 6, 15, 255)
ABYSS_2 = (5, 11, 29, 255)
ABYSS_3 = (10, 21, 48, 255)
BIO = (34, 211, 238)              # --bioluminescence
BIO_SOFT = (103, 232, 249)        # --bioluminescence-soft
TEXT_DIM = (148, 168, 192)
BORDER = (34, 211, 238, 46)       # rgba(34,211,238,0.18)

# Where to wipe and where to repaint. The source artwork's halo is centered
# slightly left of the bulb disc, so a single circular erase covers both,
# then we paint a clean cyan disc back at the bulb's actual position.
ESCA_ERASE_X_PCT = 0.83        # erase mask centre — covers halo + disc
ESCA_ERASE_Y_PCT = 0.34
ESCA_ERASE_RADIUS_PCT = 0.18
ESCA_DISC_X_PCT = 0.889        # painted bulb centre — actual disc position
ESCA_DISC_Y_PCT = 0.344
ESCA_DISC_RADIUS_PCT = 0.048

# Layout: 48px outer padding, sigil ~ 224px tall, 32px gap to text block.
PAD = 48
SIGIL_H = 224
GAP = 36

WIN_FONTS = Path("C:/Windows/Fonts")
FONT_TITLE = WIN_FONTS / "segoeuib.ttf"   # Segoe UI Bold (Inter fallback)
FONT_SUB = WIN_FONTS / "segoeui.ttf"
FONT_MONO = WIN_FONTS / "consolab.ttf"    # Consolas Bold (JetBrains Mono fallback)

TITLE_SIZE = 64
SUB_SIZE = 22
PILL_SIZE = 18
TITLE_TRACK = 11   # ~ 0.18em at 64px
PILL_TRACK = 2


def read_version() -> str:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(pyproject["project"]["version"])


def make_background() -> Image.Image:
    """Reproduce the body radial gradient + .lure top linear overlay."""
    bg = Image.new("RGBA", (WIDTH, HEIGHT), ABYSS)
    px = bg.load()
    assert px is not None
    cx, cy = WIDTH / 2, 0  # ellipse "at top"
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
    # Top linear overlay: ABYSS_3 → transparent (mirrors `.lure` bg).
    overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    olpx = overlay.load()
    assert olpx is not None
    for y in range(HEIGHT):
        a = max(0, round(255 * (1 - y / HEIGHT)))
        for x in range(WIDTH):
            olpx[x, y] = (*ABYSS_3[:3], a)
    bg.alpha_composite(overlay)
    # Bottom border line (matches `.lure` border-bottom).
    ImageDraw.Draw(bg).line([(0, HEIGHT - 1), (WIDTH, HEIGHT - 1)], fill=BORDER, width=1)
    return bg


def load_sigil() -> Image.Image:
    """Load the silhouette, wipe the bulb/halo region, paint a clean bulb back."""
    sigil = Image.open(SIGIL_SRC).convert("RGBA")
    ratio = SIGIL_H / sigil.height
    new_w = round(sigil.width * ratio)
    sigil = sigil.resize((new_w, SIGIL_H), Image.LANCZOS)
    # Wipe the entire bulb-area circle (halo + original disc).
    ex = round(new_w * ESCA_ERASE_X_PCT)
    ey = round(SIGIL_H * ESCA_ERASE_Y_PCT)
    er = round(new_w * ESCA_ERASE_RADIUS_PCT)
    mask = Image.new("L", sigil.size, 255)
    ImageDraw.Draw(mask).ellipse((ex - er, ey - er, ex + er, ey + er), fill=0)
    mask = mask.filter(ImageFilter.GaussianBlur(0.6))
    alpha = sigil.split()[3]
    new_alpha = Image.new("L", sigil.size)
    ap = alpha.load()
    mp = mask.load()
    np_ = new_alpha.load()
    assert ap is not None and mp is not None and np_ is not None
    for y in range(sigil.size[1]):
        for x in range(sigil.size[0]):
            np_[x, y] = (ap[x, y] * mp[x, y]) // 255
    sigil.putalpha(new_alpha)
    # Paint a clean cyan disc at the bulb's actual location.
    dx = round(new_w * ESCA_DISC_X_PCT)
    dy = round(SIGIL_H * ESCA_DISC_Y_PCT)
    dr = round(new_w * ESCA_DISC_RADIUS_PCT)
    disc_draw = ImageDraw.Draw(sigil)
    disc_draw.ellipse((dx - dr, dy - dr, dx + dr, dy + dr), fill=(*BIO_SOFT, 255))
    return sigil


def sigil_halo(sigil: Image.Image) -> Image.Image:
    """Soft cyan ambient drop-shadow around the sigil (matches CSS filter)."""
    alpha = sigil.split()[3]
    halo = Image.new("RGBA", sigil.size, (*BIO, 0))
    halo.putalpha(alpha.point(lambda v: min(255, int(v * 0.5))))
    return halo.filter(ImageFilter.GaussianBlur(8))


def draw_tracked_text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int] | tuple[int, int, int, int],
    track: int,
) -> int:
    """Draw `text` with per-character letter-spacing. Returns total width."""
    x, y = xy
    start_x = x
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        bbox = font.getbbox(ch)
        x += (bbox[2] - bbox[0]) + track
    return x - start_x - track if text else 0


def tracked_text_width(text: str, font: ImageFont.FreeTypeFont, track: int) -> int:
    if not text:
        return 0
    width = 0
    for ch in text:
        bbox = font.getbbox(ch)
        width += (bbox[2] - bbox[0]) + track
    return width - track


def render_title_with_glow(text: str, font: ImageFont.FreeTypeFont) -> Image.Image:
    """Title text with its cyan glow (matches CSS text-shadow on .lure__title)."""
    w = tracked_text_width(text, font, TITLE_TRACK) + 80
    h = TITLE_SIZE * 2
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(layer)
    draw_tracked_text(glow_draw, (40, h // 4), text, font, (*BIO, 200), TITLE_TRACK)
    glow = layer.filter(ImageFilter.GaussianBlur(6))
    foreground = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    fg_draw = ImageDraw.Draw(foreground)
    draw_tracked_text(fg_draw, (40, h // 4), text, font, (*BIO_SOFT, 255), TITLE_TRACK)
    glow.alpha_composite(foreground)
    return glow


def render_status_pill(version: str, font: ImageFont.FreeTypeFont) -> Image.Image:
    text = f"v{version}".upper()
    tw = tracked_text_width(text, font, PILL_TRACK)
    pad_x, pad_y = 18, 8
    w = tw + pad_x * 2
    h = PILL_SIZE + pad_y * 2 + 4
    pill = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(pill)
    radius = h // 2
    draw.rounded_rectangle((0, 0, w - 1, h - 1), radius=radius, outline=(*BIO, 200), width=1)
    draw_tracked_text(draw, (pad_x, pad_y), text, font, (*BIO_SOFT, 230), PILL_TRACK)
    return pill


def compose_banner(version: str) -> Image.Image:
    """Render the full banner: background + sigil + title/subtitle + version pill."""
    base = make_background()
    sigil = load_sigil()
    halo = sigil_halo(sigil)

    sigil_x = PAD
    sigil_y = (HEIGHT - SIGIL_H) // 2
    base.alpha_composite(halo, (sigil_x, sigil_y))
    base.alpha_composite(sigil, (sigil_x, sigil_y))

    title_font = ImageFont.truetype(str(FONT_TITLE), TITLE_SIZE)
    sub_font = ImageFont.truetype(str(FONT_SUB), SUB_SIZE)
    pill_font = ImageFont.truetype(str(FONT_MONO), PILL_SIZE)

    text_x = sigil_x + sigil.width + GAP
    title_img = render_title_with_glow("ANGLERFISH AI", title_font)
    title_y = sigil_y + 38
    base.alpha_composite(title_img, (text_x - 40, title_y - TITLE_SIZE // 2))

    sub_text = "Deep-sea SSH honeypot · AI-powered threat intelligence"
    sub_draw = ImageDraw.Draw(base)
    sub_draw.text((text_x, title_y + TITLE_SIZE + 14), sub_text, font=sub_font, fill=TEXT_DIM)

    pill = render_status_pill(version, pill_font)
    pill_x = WIDTH - PAD - pill.width
    pill_y = (HEIGHT - pill.height) // 2
    base.alpha_composite(pill, (pill_x, pill_y))
    return base


def main() -> int:
    if not SIGIL_SRC.exists():
        print(f"missing sigil: {SIGIL_SRC}", file=sys.stderr)
        return 1
    version = read_version()
    print(f"rendering banner for v{version}")
    banner = compose_banner(version)
    BANNER_OUT.parent.mkdir(parents=True, exist_ok=True)
    banner.save(BANNER_OUT, format="PNG", optimize=True)
    size_kb = BANNER_OUT.stat().st_size / 1024
    print(f"wrote {BANNER_OUT.relative_to(ROOT)} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

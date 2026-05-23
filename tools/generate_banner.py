"""Generate the README banner from the bioluminescent dashboard palette.

Output: ``assets/anglerfish-banner.png`` — static PNG (1280x320) whose
layout, palette, glow and lit esca match the dashboard ``.lure`` header
in ``src/anglerfish/dashboard/static/style.css``.

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
KELP = (15, 40, 73, 255)
BIO = (34, 211, 238)              # --bioluminescence
BIO_SOFT = (103, 232, 249)        # --bioluminescence-soft
TEXT = (226, 243, 255)
TEXT_DIM = (148, 168, 192)
BORDER = (34, 211, 238, 46)       # rgba(34,211,238,0.18)
ESCA_CORE = (180, 248, 255)       # warm-white core of the throb

# Esca centroid in the sigil. Measured directly from the bulb-tip pixels —
# the dashboard CSS uses (0.776, 0.325) which targets the stem joint instead;
# good enough for the CSS overlay's wide bloom, wrong for a tight static glow.
ESCA_X_PCT = 0.838
ESCA_Y_PCT = 0.348
# Radius (as fraction of sigil width) of the bulb-area patch we erase in the
# source artwork before painting the glow. The original PNG surrounds the
# bulb with a dotted cyan/dark halo that reads as a checkerboard at any
# zoom; this mask wipes it so the painted glow can own that region.
ESCA_PATCH_RADIUS_PCT = 0.21
# Glow disc diameter as a fraction of sigil width. Sized to roughly match
# the bulb tip + a soft halo — not the full lure span like the CSS overlay.
ESCA_GLOW_DIAMETER_PCT = 0.26

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

# Static esca: somewhere between the CSS keyframes' mid and peak, so the bulb
# reads as lit on a still page without being blown out.
ESCA_SCALE = 1.05
ESCA_OPACITY = 0.9


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
    """Load the silhouette and wipe the bulb-mesh pixels so the glow can own that area."""
    sigil = Image.open(SIGIL_SRC).convert("RGBA")
    ratio = SIGIL_H / sigil.height
    new_w = round(sigil.width * ratio)
    sigil = sigil.resize((new_w, SIGIL_H), Image.LANCZOS)
    cx = round(new_w * ESCA_X_PCT)
    cy = round(SIGIL_H * ESCA_Y_PCT)
    r = round(new_w * ESCA_PATCH_RADIUS_PCT)
    # Build a soft mask so the erase fades at the bulb edge — no hard circle.
    mask = Image.new("L", sigil.size, 255)
    mdraw = ImageDraw.Draw(mask)
    mdraw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=0)
    mask = mask.filter(ImageFilter.GaussianBlur(2))
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


def radial_glow(diameter: int, alpha: float) -> Image.Image:
    """Radial-gradient disc that fades to transparent — the throbbing esca."""
    img = Image.new("RGBA", (diameter, diameter), (0, 0, 0, 0))
    px = img.load()
    assert px is not None
    radius = diameter / 2
    for y in range(diameter):
        for x in range(diameter):
            dx = x - radius
            dy = y - radius
            d = math.sqrt(dx * dx + dy * dy) / radius
            if d >= 1:
                continue
            # Stops modeled on the CSS radial-gradient on .lure__sigil-wrap::after.
            if d < 0.25:
                a = 0.95
                r, g, b = ESCA_CORE
            elif d < 0.55:
                t = (d - 0.25) / 0.30
                a = 0.95 + (0.55 - 0.95) * t
                r = round(ESCA_CORE[0] + (BIO_SOFT[0] - ESCA_CORE[0]) * t)
                g = round(ESCA_CORE[1] + (BIO_SOFT[1] - ESCA_CORE[1]) * t)
                b = round(ESCA_CORE[2] + (BIO_SOFT[2] - ESCA_CORE[2]) * t)
            elif d < 0.75:
                t = (d - 0.55) / 0.20
                a = 0.55 + (0.18 - 0.55) * t
                r = round(BIO_SOFT[0] + (BIO[0] - BIO_SOFT[0]) * t)
                g = round(BIO_SOFT[1] + (BIO[1] - BIO_SOFT[1]) * t)
                b = round(BIO_SOFT[2] + (BIO[2] - BIO_SOFT[2]) * t)
            else:
                t = (d - 0.75) / 0.25
                a = 0.18 * (1 - t)
                r, g, b = BIO
            px[x, y] = (r, g, b, max(0, min(255, round(255 * a * alpha))))
    return img


def compose_static_base(version: str) -> tuple[Image.Image, tuple[int, int], int]:
    """Return the base banner (no esca glow), plus esca centre + glow diameter."""
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

    esca_cx = sigil_x + round(sigil.width * ESCA_X_PCT)
    esca_cy = sigil_y + round(SIGIL_H * ESCA_Y_PCT)
    glow_diameter = round(sigil.width * ESCA_GLOW_DIAMETER_PCT)
    return base, (esca_cx, esca_cy), glow_diameter


def paint_esca(base: Image.Image, centre: tuple[int, int], base_diameter: int) -> Image.Image:
    """Screen-blend the lit esca glow onto the sigil. Same intent as
    ``mix-blend-mode: screen`` on the dashboard ``.lure__sigil-wrap::after``."""
    diameter = max(2, round(base_diameter * ESCA_SCALE))
    glow = radial_glow(diameter, ESCA_OPACITY)
    out = base.copy()
    cx, cy = centre
    pos = (cx - diameter // 2, cy - diameter // 2)
    region = out.crop((pos[0], pos[1], pos[0] + diameter, pos[1] + diameter))
    blended = Image.new("RGBA", region.size, (0, 0, 0, 0))
    rp = region.load()
    gp = glow.load()
    bp = blended.load()
    assert rp is not None and gp is not None and bp is not None
    for y in range(diameter):
        for x in range(diameter):
            rr, rg, rb, ra = rp[x, y]
            gr, gg, gb, ga = gp[x, y]
            if ga == 0:
                bp[x, y] = (rr, rg, rb, ra)
                continue
            ga_n = ga / 255
            out_r = round(rr + (255 - rr) * (gr / 255) * ga_n)
            out_g = round(rg + (255 - rg) * (gg / 255) * ga_n)
            out_b = round(rb + (255 - rb) * (gb / 255) * ga_n)
            out_a = max(ra, ga)
            bp[x, y] = (out_r, out_g, out_b, out_a)
    out.paste(blended, pos)
    return out


def main() -> int:
    if not SIGIL_SRC.exists():
        print(f"missing sigil: {SIGIL_SRC}", file=sys.stderr)
        return 1
    version = read_version()
    print(f"rendering banner for v{version}")
    base, centre, glow_d = compose_static_base(version)
    banner = paint_esca(base, centre, glow_d)
    BANNER_OUT.parent.mkdir(parents=True, exist_ok=True)
    banner.save(BANNER_OUT, format="PNG", optimize=True)
    size_kb = BANNER_OUT.stat().st_size / 1024
    print(f"wrote {BANNER_OUT.relative_to(ROOT)} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

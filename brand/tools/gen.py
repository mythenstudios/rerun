"""Generates the Rerun brand kit: SVG (text as paths), PNG, ICO."""
import os, subprocess, sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen
from PIL import Image, ImageDraw

FONTS = sys.argv[1]
OUT = sys.argv[2]

FELS, SCHNEE = "#0b0b0b", "#f7f7f5"
MUTED_N, MUTED_S = "#9c9c98", "#5c5c59"
LINE_N, LINE_S = "#2e2e2c", "#bdbdb9"

# Mark: 8 x 7 cells. (x, y, w, h) in cells
MARK = [(0, 0, 1, 1), (0, 1, 2, 1), (0, 2, 4, 1), (0, 3, 5, 1), (0, 4, 4, 1), (0, 5, 2, 1), (0, 6, 1, 1), (6, 6, 2, 1)]

fonts = {k: TTFont(os.path.join(FONTS, f)) for k, f in
         {"mono": "mono500.ttf", "sans": "sans400.ttf", "sans6": "sans600.ttf"}.items()}


def text_path(font_key, text, size, x, baseline, tracking_em=0.0):
    """Returns (svg_path_d, ink_left, ink_right, advance_end)."""
    f = fonts[font_key]
    gs = f.getGlyphSet()
    cmap = f.getBestCmap()
    upm = f["head"].unitsPerEm
    s = size / upm
    d, pen_x = [], x
    ink_l, ink_r = None, None
    for i, ch in enumerate(text):
        gname = cmap[ord(ch)]
        g = gs[gname]
        sp = SVGPathPen(gs)
        g.draw(TransformPen(sp, (s, 0, 0, -s, pen_x, baseline)))
        cmd = sp.getCommands()
        if cmd:
            d.append(cmd)
            bp = BoundsPen(gs)
            g.draw(bp)
            if bp.bounds:
                l = pen_x + bp.bounds[0] * s
                r = pen_x + bp.bounds[2] * s
                ink_l = l if ink_l is None else min(ink_l, l)
                ink_r = r if ink_r is None else max(ink_r, r)
        pen_x += g.width * s
        if i < len(text) - 1:
            pen_x += tracking_em * size
    return " ".join(d), ink_l, ink_r, pen_x


def mark_rects(c, ox, oy, fill, cursor=True):
    cells = MARK if cursor else MARK[:-1]
    return "".join(f'<rect x="{ox + x*c:g}" y="{oy + y*c:g}" width="{w*c:g}" height="{h*c:g}"/>' for x, y, w, h in cells).join(
        [f'<g fill="{fill}" shape-rendering="crispEdges">', "</g>"])


def svg(w, h, body, bg=None):
    bgr = f'<rect width="{w:g}" height="{h:g}" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:g}" height="{h:g}" viewBox="0 0 {w:g} {h:g}">'
            f'{bgr}{body}</svg>\n')


def write(path, content):
    p = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(content)
    return p


def raster(svg_path, png_path, w=None):
    p = os.path.join(OUT, png_path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    args = ["rsvg-convert", svg_path, "-o", p]
    if w:
        args[1:1] = ["-w", str(w)]
    subprocess.run(args, check=True)


# Wordmark: "rerun" + cursor block. Grid c: cap height = 7c.
CAP = fonts["mono"]["OS/2"].sCapHeight / 1000


def wordmark(c, x, baseline, fill):
    size = 7 * c / CAP
    d, l, r, end = text_path("mono", "rerun", size, x, baseline)
    adv = 0.6 * size
    cur_x = end + 0.12 * size
    cur = f'<rect x="{cur_x:g}" y="{baseline - c:g}" width="{4*c:g}" height="{c:g}"/>'
    return f'<g fill="{fill}"><path d="{d}"/>{cur}</g>', l, cur_x + 4 * c


def lockup(c, ox, oy, fill):
    """Mark + wordmark. oy = top edge of the mark. Returns (body, width)."""
    # In the lockup the wordmark carries the cursor, the mark only the triangle: "▶ rerun_"
    m = mark_rects(c, ox, oy, fill, cursor=False)
    gap = 3 * c
    tmp, l, _ = wordmark(c, 0, 0, fill)
    shift = ox + 5 * c + gap - l
    wm, l2, r2 = wordmark(c, shift, oy + 7 * c, fill)
    return m + wm, r2 - ox


def label(text, size, x, baseline, fill):
    d, l, r, end = text_path("mono", text, size, x, baseline, tracking_em=0.32)
    return f'<path fill="{fill}" d="{d}"/>', end


os.makedirs(OUT, exist_ok=True)

# ---------- Logo SVGs ----------
for name, col in [("schnee", SCHNEE), ("fels", FELS)]:
    write(f"logo/rerun-mark-{name}.svg", svg(160, 140, mark_rects(20, 0, 0, col)))
    c = 10
    wm, l, r = wordmark(c, 0, 70, col)
    w = r - l
    # Ink of "rerun" starts at l; top of the x-height
    xh = fonts["mono"]["OS/2"].sxHeight / 1000 * (7 * c / CAP)
    top = 70 - xh
    body = f'<g transform="translate({-l:g} {-top:g})">{wm}</g>'
    write(f"logo/rerun-wordmark-{name}.svg", svg(round(w, 2), round(70 - top, 2), body))
    lb, lw = lockup(10, 0, 0, col)
    write(f"logo/rerun-lockup-{name}.svg", svg(round(lw, 2), 70, lb))
    # Lockup with sender line
    muted = MUTED_N if name == "schnee" else MUTED_S
    lb2, lw2 = lockup(10, 0, 0, col)
    text_x = 5 * 10 + 30
    lab, lab_end = label("BY MYTHEN STUDIOS", 13, text_x, 70 + 34, muted)
    write(f"logo/rerun-lockup-mythen-{name}.svg", svg(round(max(lw2, lab_end), 2), 108, lb2 + lab))

# ---------- Pixel icons (exact) ----------
def icon(size, bg=FELS, fg=SCHNEE, rounded=True):
    table = {16: 2, 24: 2, 32: 3, 48: 4, 64: 6, 128: 12, 256: 22, 512: 44, 1024: 88}
    c = table[size]
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    dr = ImageDraw.Draw(img)
    rad = round(size * 0.1875) if (rounded and size >= 48) else 0
    if rad:
        dr.rounded_rectangle([0, 0, size - 1, size - 1], radius=rad, fill=bg)
    else:
        dr.rectangle([0, 0, size - 1, size - 1], fill=bg)
    ox = (size - 8 * c) // 2
    oy = (size - 7 * c) // 2
    for x, y, w, h in MARK:
        dr.rectangle([ox + x * c, oy + y * c, ox + (x + w) * c - 1, oy + (y + h) * c - 1], fill=fg)
    return img


ICON_SIZES = [16, 24, 32, 48, 64, 128, 256, 512, 1024]
icons = {s: icon(s) for s in ICON_SIZES}
for s, im in icons.items():
    p = os.path.join(OUT, f"icon/app-icon-{s}.png")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    im.save(p)

ico_sizes = [16, 24, 32, 48, 64, 128, 256]
big = icons[256]
big.save(os.path.join(OUT, "icon/rerun.ico"), sizes=[(s, s) for s in ico_sizes],
         append_images=[icons[s] for s in ico_sizes if s != 256])
fav = [16, 32, 48]
icons[48].save(os.path.join(OUT, "icon/favicon.ico"), sizes=[(s, s) for s in fav],
               append_images=[icons[s] for s in fav if s != 48])
write("icon/favicon.svg", svg(16, 16, mark_rects(2, 0, 1, SCHNEE), bg=FELS).replace(
    '<svg ', '<svg shape-rendering="crispEdges" ', 1))

# Mark transparent, large (for Discord, itch.io, presentations)
for name, col in [("schnee", SCHNEE), ("fels", FELS)]:
    im = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
    dr = ImageDraw.Draw(im)
    c = 48
    ox, oy = (512 - 8 * c) // 2, (512 - 7 * c) // 2
    for x, y, w, h in MARK:
        dr.rectangle([ox + x * c, oy + y * c, ox + (x + w) * c - 1, oy + (y + h) * c - 1], fill=col)
    im.save(os.path.join(OUT, f"logo/rerun-mark-{name}-512.png"))

# Avatar (square, works with a round crop)
av = Image.new("RGB", (512, 512), FELS)
dr = ImageDraw.Draw(av)
c = 36
ox, oy = (512 - 8 * c) // 2, (512 - 7 * c) // 2
for x, y, w, h in MARK:
    dr.rectangle([ox + x * c, oy + y * c, ox + (x + w) * c - 1, oy + (y + h) * c - 1], fill=SCHNEE)
os.makedirs(os.path.join(OUT, "social"), exist_ok=True)
av.save(os.path.join(OUT, "social/avatar-512.png"))

# ---------- GitHub Social Preview 1280x640 ----------
W, H = 1280, 640
c = 20
lb, lw = lockup(c, 96, 150, SCHNEE)
tag_d, _, _, _ = text_path("sans", "Old games. New systems.", 40, 96, 150 + 7 * c + 96)
sub_d, _, _, _ = text_path("sans", "Compatibility fixes for classic PC games on Windows 11.", 24, 96, 150 + 7 * c + 96 + 44)
line = f'<rect x="96" y="{H - 112}" width="{W - 192}" height="1" fill="{LINE_N}"/>'
lab1, _ = label("BY MYTHEN STUDIOS", 14, 96, H - 72, MUTED_N)
r_text = "NO BACKGROUND PROCESS · FULLY REVERSIBLE"
_, l_, r_, end_ = text_path("mono", r_text, 14, 0, 0, tracking_em=0.32)
lab2, _ = label(r_text, 14, W - 96 - end_, H - 72, MUTED_N)
body = (lb + f'<path fill="{SCHNEE}" d="{tag_d}"/>' + f'<path fill="{MUTED_N}" d="{sub_d}"/>' + line + lab1 + lab2)
sp = write("social/github-social-preview.svg", svg(W, H, body, bg=FELS))
raster(sp, "social/github-social-preview.png")

# ---------- README header 1280x320 (dark + light) ----------
for name, bg, fg, muted in [("dark", FELS, SCHNEE, MUTED_N), ("light", SCHNEE, FELS, MUTED_S)]:
    W, H = 1280, 320
    c = 12
    lb, lw = lockup(c, 64, (H - 7 * c) // 2, fg)
    t = "OLD GAMES. NEW SYSTEMS."
    _, _, _, end_ = text_path("mono", t, 14, 0, 0, tracking_em=0.32)
    lab, _ = label(t, 14, W - 64 - end_, (H - 7 * c) // 2 + 7 * c, muted)
    sp = write(f"social/readme-header-{name}.svg", svg(W, H, lb + lab, bg=bg))
    raster(sp, f"social/readme-header-{name}.png")

# PNG versions of the lockups
for name in ["schnee", "fels"]:
    raster(os.path.join(OUT, f"logo/rerun-lockup-{name}.svg"), f"logo/rerun-lockup-{name}-1200.png", 1200)
    raster(os.path.join(OUT, f"logo/rerun-lockup-mythen-{name}.svg"), f"logo/rerun-lockup-mythen-{name}-1200.png", 1200)

print("ok")

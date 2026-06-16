#!/usr/bin/env python3
"""Generate the DirectGate Manager icon set used by Tauri.

Produces a small, flat "gateway" mark: a rounded blue tile with a white
chevron pointing through a vertical gate bar. Run from this directory:

    python3 gen_icons.py

Output: 32x32.png, 128x128.png, 128x128@2x.png, icon.png, icon.ico, icon.icns
"""

from PIL import Image, ImageDraw

BASE = 1024
BG_TOP = (37, 99, 235)      # #2563eb
BG_BOTTOM = (29, 64, 175)   # #1d40af
FG = (255, 255, 255)


def vertical_gradient(size, top, bottom):
    img = Image.new("RGB", (size, size), top)
    px = img.load()
    for y in range(size):
        t = y / (size - 1)
        r = int(top[0] + (bottom[0] - top[0]) * t)
        g = int(top[1] + (bottom[1] - top[1]) * t)
        b = int(top[2] + (bottom[2] - top[2]) * t)
        for x in range(size):
            px[x, y] = (r, g, b)
    return img


def rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def render(size):
    grad = vertical_gradient(size, BG_TOP, BG_BOTTOM)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    img.paste(grad, (0, 0), rounded_mask(size, int(size * 0.22)))

    d = ImageDraw.Draw(img)
    s = size / 1024.0
    lw = int(80 * s)

    # vertical "gate" bar
    bar_x = int(360 * s)
    d.line([(bar_x, int(300 * s)), (bar_x, int(724 * s))], fill=FG, width=lw)

    # chevron pointing right (traffic passing through the gate)
    d.line(
        [(int(520 * s), int(330 * s)),
         (int(720 * s), int(512 * s)),
         (int(520 * s), int(694 * s))],
        fill=FG, width=lw, joint="curve",
    )
    return img


def main():
    base = render(BASE)

    base.resize((32, 32), Image.LANCZOS).save("32x32.png")
    base.resize((128, 128), Image.LANCZOS).save("128x128.png")
    base.resize((256, 256), Image.LANCZOS).save("128x128@2x.png")
    base.resize((512, 512), Image.LANCZOS).save("icon.png")

    base.save(
        "icon.ico",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    base.save("icon.icns")
    print("icons generated")


if __name__ == "__main__":
    main()

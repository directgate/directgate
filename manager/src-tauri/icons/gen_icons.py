#!/usr/bin/env python3
"""Generate the DirectGate Manager icon set used by Tauri from a source logo.

Takes a (transparent) source PNG, trims its empty margins, centers it on a
square canvas with consistent padding, and exports every size Tauri bundles.
Run from this directory:

    python3 gen_icons.py                       # uses input.png
    python3 gen_icons.py path/to/other.png     # use a different source

Output: 32x32.png, 128x128.png, 128x128@2x.png, icon.png, icon.ico, icon.icns
"""

import sys

from PIL import Image

BASE = 1024
# Fraction of the canvas left empty on each side, so the mark is not edge-to-edge.
PAD = 0.06
DEFAULT_SOURCE = "input.png"


def load_square_logo(path, size=BASE, pad=PAD):
    """Return a `size`x`size` RGBA image with the trimmed logo centered."""
    logo = Image.open(path).convert("RGBA")

    # Trim fully-transparent margins so every source frames the same way.
    bbox = logo.split()[-1].getbbox()
    if bbox:
        logo = logo.crop(bbox)

    # Scale to fit inside the padded box, preserving aspect ratio.
    box = int(size * (1 - 2 * pad))
    scale = min(box / logo.width, box / logo.height)
    new_w = max(1, round(logo.width * scale))
    new_h = max(1, round(logo.height * scale))
    logo = logo.resize((new_w, new_h), Image.LANCZOS)

    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.paste(logo, ((size - new_w) // 2, (size - new_h) // 2), logo)
    return canvas


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SOURCE
    base = load_square_logo(source)

    base.resize((32, 32), Image.LANCZOS).save("32x32.png")
    base.resize((128, 128), Image.LANCZOS).save("128x128.png")
    base.resize((256, 256), Image.LANCZOS).save("128x128@2x.png")
    base.resize((512, 512), Image.LANCZOS).save("icon.png")

    base.save(
        "icon.ico",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    base.save("icon.icns")
    print(f"icons generated from {source}")


if __name__ == "__main__":
    main()

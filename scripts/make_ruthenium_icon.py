#!/usr/bin/env python3
"""Generate the canonical Ruthenium app icon and Android/Play assets."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, PngImagePlugin


CANVAS = 1080
AA = 4
VISIBLE_INSET = 180
PLAY_SIZE = 512
PLAY_ARTWORK = 384

BACKGROUND_HEX = "#101923"
SILVER_HEX = "#EEF1F5"

BACKGROUND = (16, 25, 35, 255)
SILVER = (238, 241, 245, 255)
THEMED_BACKGROUND = (220, 231, 248, 255)
THEMED_FOREGROUND = (57, 82, 126, 255)


GLOBE_CENTER = (540, 540)
GLOBE_RADIUS = 236
GLOBE_STROKE = 46
MERIDIAN_RX = 108
MERIDIAN_STROKE = 40
LATITUDE_STROKE = 40
ARTWORK_DIAMETER = 2 * GLOBE_RADIUS + GLOBE_STROKE
ROUND_OPTICAL_OFFSET = (1, 0)

ANDROID_DENSITIES = {
    "mdpi": (48, 108),
    "hdpi": (72, 162),
    "xhdpi": (96, 216),
    "xxhdpi": (144, 324),
    "xxxhdpi": (192, 432),
}


def _s(value: float) -> int:
    return round(value * AA)


def _scaled_box(box: tuple[float, float, float, float]) -> tuple[int, int, int, int]:
    return tuple(_s(value) for value in box)  # type: ignore[return-value]


def _cubic_points(
    p0: tuple[float, float],
    p1: tuple[float, float],
    p2: tuple[float, float],
    p3: tuple[float, float],
    segments: int,
) -> list[tuple[int, int]]:
    points: list[tuple[int, int]] = []
    for index in range(segments + 1):
        t = index / segments
        one_minus_t = 1 - t
        x = (
            one_minus_t**3 * p0[0]
            + 3 * one_minus_t**2 * t * p1[0]
            + 3 * one_minus_t * t**2 * p2[0]
            + t**3 * p3[0]
        )
        y = (
            one_minus_t**3 * p0[1]
            + 3 * one_minus_t**2 * t * p1[1]
            + 3 * one_minus_t * t**2 * p2[1]
            + t**3 * p3[1]
        )
        points.append((_s(x), _s(y)))
    return points


def _arc_points(
    center: tuple[float, float],
    radius: float,
    start: float,
    end: float,
    segments: int,
) -> list[tuple[int, int]]:
    points: list[tuple[int, int]] = []
    for index in range(segments + 1):
        angle = math.radians(start + (end - start) * index / segments)
        points.append(
            (
                _s(center[0] + radius * math.cos(angle)),
                _s(center[1] + radius * math.sin(angle)),
            )
        )
    return points


def _round_caps(
    draw: ImageDraw.ImageDraw,
    points: Iterable[tuple[int, int]],
    width: int,
    fill: tuple[int, int, int, int],
) -> None:
    points = list(points)
    radius = width // 2
    for x, y in (points[0], points[-1]):
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=fill)


def _background(size: int) -> Image.Image:
    return Image.new("RGBA", (size, size), BACKGROUND)


def _fit_centered(source: Image.Image, canvas_size: int, box_size: int) -> Image.Image:
    bounds = source.getchannel("A").getbbox()
    if bounds is None:
        raise ValueError("Foreground is empty")
    source = source.crop(bounds)
    scale = min(box_size / source.width, box_size / source.height)
    target = (round(source.width * scale), round(source.height * scale))
    source = source.resize(target, Image.Resampling.LANCZOS)
    result = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    result.alpha_composite(source, ((canvas_size - target[0]) // 2, (canvas_size - target[1]) // 2))
    return result


def _recolor_alpha(source: Image.Image, color: tuple[int, int, int, int]) -> Image.Image:
    result = Image.new("RGBA", source.size, color)
    result.putalpha(source.getchannel("A"))
    return result


def _mask(size: int, kind: str) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    inset = round(size * VISIBLE_INSET / CANVAS)
    box = (inset, inset, size - inset, size - inset)
    if kind == "circle":
        draw.ellipse(box, fill=255)
    elif kind == "squircle":
        draw.rounded_rectangle(box, radius=round(size * 210 / CANVAS), fill=255)
    elif kind == "rounded-square":
        draw.rounded_rectangle(box, radius=round(size * 105 / CANVAS), fill=255)
    else:
        raise ValueError(kind)
    return mask


def _svg_document(body: str, size: int = CANVAS, background: bool = False) -> str:
    background_rect = f'  <rect width="{size}" height="{size}" fill="{BACKGROUND_HEX}"/>\n' if background else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 {size} {size}">\n{background_rect}{body}\n</svg>\n'
    )


def _save_png(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    png_info = PngImagePlugin.PngInfo()
    png_info.add(b"sRGB", b"\x00")
    image.save(path, optimize=True, compress_level=9, pnginfo=png_info)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _legacy_icon(source: Image.Image) -> Image.Image:
    mask = Image.new("L", source.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, source.width - 1, source.height - 1), fill=255)
    result = source.copy()
    result.putalpha(mask)
    return result


def _android_vector(
    color: str,
    offset: tuple[int, int] = (0, 0),
) -> str:
    dx, dy = offset
    left = 540 + dx - MERIDIAN_RX
    right = 540 + dx + MERIDIAN_RX
    center_y = 540 + dy
    return f'''<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="1080"
    android:viewportHeight="1080">
    <path
        android:fillColor="#00000000"
        android:strokeColor="{color}"
        android:strokeWidth="40"
        android:pathData="M{left},{center_y} A108,236 0,1 0,{right},{center_y} A108,236 0,1 0,{left},{center_y}" />
    <path
        android:fillColor="#00000000"
        android:strokeColor="{color}"
        android:strokeWidth="40"
        android:pathData="M{307 + dx},{512 + dy} C{418 + dx},{568 + dy} {662 + dx},{568 + dy} {773 + dx},{512 + dy}" />
    <path
        android:fillColor="#00000000"
        android:strokeColor="{color}"
        android:strokeWidth="46"
        android:strokeLineCap="round"
        android:pathData="M{715.38 + dx:g},{697.91 + dy:g} A236,236 0,1 1,{764.45 + dx:g},{612.93 + dy:g}" />
</vector>
'''


def _write_android_resources(
    output_dir: Path,
    foreground: Image.Image,
    background: Image.Image,
    round_master: Image.Image,
) -> None:
    android_root = output_dir / "android-res"
    legacy = _legacy_icon(round_master)
    for density, (legacy_size, adaptive_size) in ANDROID_DENSITIES.items():
        resource_dir = android_root / "res_chromium_base" / f"mipmap-{density}"
        _save_png(
            legacy.resize((legacy_size, legacy_size), Image.Resampling.LANCZOS),
            resource_dir / "app_icon.png",
        )
        _save_png(
            foreground.resize((adaptive_size, adaptive_size), Image.Resampling.LANCZOS),
            resource_dir / "layered_app_icon.png",
        )
        _save_png(
            background.resize((adaptive_size, adaptive_size), Image.Resampling.LANCZOS),
            resource_dir / "layered_app_icon_background.png",
        )

    _write_text(
        android_root / "res_chromium_base/drawable/themed_app_icon.xml",
        _android_vector("#000000"),
    )
    _write_text(
        android_root
        / "res_chromium_base/mipmap-nodpi/layered_app_icon_foreground.xml",
        _android_vector(SILVER_HEX, ROUND_OPTICAL_OFFSET),
    )

    adaptive_icon = '''<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/layered_app_icon_background" />
    <foreground android:drawable="@mipmap/layered_app_icon" />
    <monochrome android:drawable="@drawable/themed_app_icon" />
</adaptive-icon>
'''
    round_icon = '''<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/layered_app_icon_background" />
    <foreground android:drawable="@mipmap/layered_app_icon_foreground" />
    <monochrome android:drawable="@drawable/themed_app_icon" />
</adaptive-icon>
'''
    _write_text(android_root / "res_base/drawable/ic_launcher.xml", adaptive_icon)
    _write_text(android_root / "res_base/drawable/ic_launcher_round.xml", round_icon)


def render_foreground(
    monochrome: bool = False,
    offset: tuple[int, int] = (0, 0),
) -> Image.Image:
    image = Image.new("RGBA", (CANVAS * AA, CANVAS * AA), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    color = (255, 255, 255, 255) if monochrome else SILVER
    center = (GLOBE_CENTER[0] + offset[0], GLOBE_CENTER[1] + offset[1])

    draw.ellipse(
        _scaled_box(
            (
                center[0] - MERIDIAN_RX,
                center[1] - GLOBE_RADIUS,
                center[0] + MERIDIAN_RX,
                center[1] + GLOBE_RADIUS,
            )
        ),
        outline=color,
        width=_s(MERIDIAN_STROKE),
    )

    latitude = _cubic_points(
        (307 + offset[0], 512 + offset[1]),
        (418 + offset[0], 568 + offset[1]),
        (662 + offset[0], 568 + offset[1]),
        (773 + offset[0], 512 + offset[1]),
        96,
    )
    draw.line(latitude, fill=color, width=_s(LATITUDE_STROKE), joint="curve")

    outer = _arc_points(center, GLOBE_RADIUS, 42, 378, 240)
    draw.line(outer, fill=color, width=_s(GLOBE_STROKE), joint="curve")
    _round_caps(draw, outer, _s(GLOBE_STROKE), color)

    return image.resize((CANVAS, CANVAS), Image.Resampling.LANCZOS)


def _foreground_svg(
    monochrome: bool = False,
    offset: tuple[int, int] = (0, 0),
) -> str:
    color = "#FFFFFF" if monochrome else SILVER_HEX
    dx, dy = offset
    return f"""  <ellipse fill="none" stroke="{color}" stroke-width="40" cx="{540 + dx}" cy="{540 + dy}" rx="108" ry="236"/>
  <path fill="none" stroke="{color}" stroke-width="40" d="M{307 + dx},{512 + dy} C{418 + dx},{568 + dy} {662 + dx},{568 + dy} {773 + dx},{512 + dy}"/>
  <path fill="none" stroke="{color}" stroke-width="46" stroke-linecap="round" d="M{715.38 + dx:g},{697.91 + dy:g} A236,236 0 1 1 {764.45 + dx:g},{612.93 + dy:g}"/>"""


def _masked_tile(
    composite: Image.Image,
    kind: str,
    themed_foreground: Image.Image | None = None,
) -> Image.Image:
    source = composite
    if themed_foreground is not None:
        source = Image.new("RGBA", composite.size, THEMED_BACKGROUND)
        source.alpha_composite(_recolor_alpha(themed_foreground, THEMED_FOREGROUND))
    source = source.copy()
    source.putalpha(_mask(CANVAS, kind))
    crop = (VISIBLE_INSET, VISIBLE_INSET, CANVAS - VISIBLE_INSET, CANVAS - VISIBLE_INSET)
    return source.crop(crop).resize((240, 240), Image.Resampling.LANCZOS)


def build(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    foreground = render_foreground(False)
    monochrome = render_foreground(True)
    background = _background(CANVAS)
    master = background.copy()
    master.alpha_composite(foreground)
    round_foreground = render_foreground(False, ROUND_OPTICAL_OFFSET)
    round_monochrome = render_foreground(True, ROUND_OPTICAL_OFFSET)
    round_master = background.copy()
    round_master.alpha_composite(round_foreground)

    _write_android_resources(output_dir, foreground, background, round_master)

    _save_png(foreground, output_dir / "ruthenium-adaptive-foreground.png")
    _save_png(background, output_dir / "ruthenium-adaptive-background.png")
    _save_png(monochrome, output_dir / "ruthenium-adaptive-monochrome.png")
    _save_png(master, output_dir / "ruthenium-adaptive-master.png")
    _save_png(round_foreground, output_dir / "ruthenium-round-foreground.png")
    _save_png(round_monochrome, output_dir / "ruthenium-round-monochrome.png")
    _save_png(round_master, output_dir / "ruthenium-round-master.png")

    _write_text(
        output_dir / "ruthenium-adaptive-foreground.svg",
        _svg_document(_foreground_svg(False)),
    )
    _write_text(
        output_dir / "ruthenium-adaptive-background.svg",
        _svg_document("", background=True),
    )
    _write_text(
        output_dir / "ruthenium-adaptive-monochrome.svg",
        _svg_document(_foreground_svg(True)),
    )
    _write_text(
        output_dir / "ruthenium-adaptive-master.svg",
        _svg_document(_foreground_svg(False), background=True),
    )
    _write_text(
        output_dir / "ruthenium-round-foreground.svg",
        _svg_document(_foreground_svg(False, ROUND_OPTICAL_OFFSET)),
    )
    _write_text(
        output_dir / "ruthenium-round-monochrome.svg",
        _svg_document(_foreground_svg(True, ROUND_OPTICAL_OFFSET)),
    )
    _write_text(
        output_dir / "ruthenium-round-master.svg",
        _svg_document(_foreground_svg(False, ROUND_OPTICAL_OFFSET), background=True),
    )

    play_foreground = _fit_centered(foreground, PLAY_SIZE, PLAY_ARTWORK)
    play = _background(PLAY_SIZE)
    play.alpha_composite(play_foreground)
    _save_png(play, output_dir / "ruthenium-google-play-512.png")

    play_scale = PLAY_ARTWORK / ARTWORK_DIAMETER
    play_svg_body = (
        f'  <g transform="translate(256 256) scale({play_scale:.8f}) translate(-540 -540)">\n'
        f"{_foreground_svg(False)}\n  </g>"
    )
    _write_text(
        output_dir / "ruthenium-google-play-512.svg",
        _svg_document(play_svg_body, PLAY_SIZE, background=True),
    )

    tiles = [
        _masked_tile(round_master, "circle"),
        _masked_tile(master, "squircle"),
        _masked_tile(master, "rounded-square"),
        _masked_tile(round_master, "circle", round_monochrome),
    ]
    board = Image.new("RGBA", (1080, 300), (240, 243, 247, 255))
    for index, tile in enumerate(tiles):
        board.alpha_composite(tile, (30 + index * 270, 30))
    _save_png(board, output_dir / "ruthenium-mask-previews.png")

    sizes = [192, 96, 48, 32]
    size_board = Image.new("RGBA", (560, 240), (240, 243, 247, 255))
    x = 20
    for size in sizes:
        icon = tiles[0].resize((size, size), Image.Resampling.LANCZOS)
        size_board.alpha_composite(icon, (x, 20))
        x += size + 28
    _save_png(size_board, output_dir / "ruthenium-size-previews.png")

    bounds = foreground.getchannel("A").point(lambda value: 255 if value >= 8 else 0).getbbox()
    if bounds is None or bounds[0] < 280 or bounds[1] < 280 or bounds[2] > 800 or bounds[3] > 800:
        raise AssertionError(f"Globe escaped the intended 52 dp keyline: {bounds}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path, nargs="?", default=Path("assets/ruthenium-icon"))
    args = parser.parse_args()
    build(args.output_dir)


if __name__ == "__main__":
    main()

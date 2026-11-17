"""Regenerate the PNG and ICO exports in assets/export/ from logo.svg and icon-16.svg.

Windows only: renders with headless Microsoft Edge, so the output matches what a browser draws.
Run from anywhere: python assets/export-icons.py
"""

import re
import struct
import subprocess
import tempfile
from pathlib import Path

ASSETS = Path(__file__).resolve().parent
OUT = ASSETS / "export"
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
NAVY, PALE = "#1f2a44", "#e6ebf5"


def mark(svg_name: str, colour: str) -> tuple[str, str]:
    """The drawing of an SVG (its <g class="mark">), recoloured, plus its viewBox size."""
    text = (ASSETS / svg_name).read_text(encoding="utf-8")
    size = re.search(r'viewBox="0 0 (\d+) \d+"', text).group(1)
    group = re.search(r"<g class=\"mark\".*?</g>", text, re.S).group(0)
    stroke = re.search(r"stroke-width: ([\d.]+)", text).group(1)
    group = group.replace('class="mark"', f'fill="none" stroke="{colour}" stroke-width="{stroke}"', 1)
    return re.sub(r"<!--.*?-->", "", group, flags=re.S), size


def transparent(svg_name: str, colour: str) -> str:
    group, size = mark(svg_name, colour)
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}">{group}</svg>'


def tile(svg_name: str) -> str:
    """The pale mark on a navy rounded square: readable on light and dark backgrounds alike."""
    group, size = mark(svg_name, PALE)
    s = int(size)
    pad = s * 0.08
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}">'
        f'<rect width="{s}" height="{s}" rx="{s * 0.22}" fill="{NAVY}"/>'
        f'<g transform="translate({pad} {pad}) scale({(s - 2 * pad) / s})">{group}</g></svg>'
    )


def social() -> str:
    group, _ = mark("logo.svg", PALE)
    return f"""<div style="width:1280px;height:640px;background:{NAVY};display:flex;align-items:center;
      justify-content:center;gap:48px;font-family:'Segoe UI',sans-serif;color:{PALE}">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="300" height="300">{group}</svg>
      <div><div style="font-size:112px;font-weight:600;letter-spacing:-2px">Tiresias</div>
      <div style="font-size:36px;opacity:.85;max-width:620px">Let AI agents and tools use your
      credentials without ever seeing them.</div></div></div>"""


def render(body: str, width: int, height: int, target: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "page.html"
        page.write_text(
            "<!doctype html><meta charset=utf-8><style>html,body{margin:0;background:transparent}"
            f"body>svg{{display:block;width:{width}px;height:{height}px}}</style>{body}",
            encoding="utf-8",
        )
        subprocess.run(
            [str(EDGE), "--headless=new", "--disable-gpu", "--hide-scrollbars",
             "--force-device-scale-factor=1", "--default-background-color=00000000",
             f"--window-size={width},{height}", f"--screenshot={target}", page.as_uri()],
            check=True, capture_output=True,
        )


def ico(pngs: list[Path], target: Path) -> None:
    """Pack PNG images into one .ico (PNG-compressed entries, supported since Windows Vista)."""
    blobs = [p.read_bytes() for p in pngs]
    sizes = [struct.unpack(">I", b[16:20])[0] for b in blobs]
    offset = 6 + 16 * len(blobs)
    header = struct.pack("<HHH", 0, 1, len(blobs))
    entries = b""
    for size, blob in zip(sizes, blobs):
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    target.write_bytes(header + entries + b"".join(blobs))


def main() -> None:
    OUT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        def frames(name: str, make, sizes: list[int]) -> list[Path]:
            paths = []
            for size in sizes:
                path = work / f"{name}-{size}.png"
                # The 16 px drawing up to 32 px; the full mark above that.
                render(make("icon-16.svg" if size <= 32 else "logo.svg"), size, size, path)
                paths.append(path)
            return paths

        # Exe and installer icon (Explorer, taskbar, Start): the tile.
        ico(frames("app", tile, [16, 20, 24, 32, 48, 64, 256]), OUT / "tiresias.ico")
        # Tray icons: transparent, one per taskbar theme; the app picks one at runtime.
        tray = [16, 20, 24, 32]
        ico(frames("tray-light", lambda n: transparent(n, NAVY), tray), OUT / "tray-light-theme.ico")
        ico(frames("tray-dark", lambda n: transparent(n, PALE), tray), OUT / "tray-dark-theme.ico")

    render(tile("logo.svg"), 128, 128, OUT / "nuget-icon.png")
    render(transparent("logo.svg", NAVY), 512, 512, OUT / "logo-512.png")
    render(transparent("logo.svg", PALE), 512, 512, OUT / "logo-512-dark.png")
    render(social(), 1280, 640, OUT / "social-preview.png")
    for path in sorted(OUT.iterdir()):
        print(f"{path.name:28} {path.stat().st_size:>8} bytes")


if __name__ == "__main__":
    main()

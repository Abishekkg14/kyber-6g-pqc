#!/usr/bin/env python3
"""Fetch the pictograms and the photograph used in the figures. Only sources whose licence allows reuse in a
publication are used (a picture found with a web image search usually may not be reprinted without permission).

1. Pictograms: Material Design Icons by Pictogrammers (https://pictogrammers.com/library/mdi/), Apache-2.0,
   solid black glyphs on a 24 x 24 grid, fetched from the jsDelivr mirror of the npm package at a pinned version.
   For every role the preferred names are looked up in the package index; if none exists the index is searched by
   keyword. Each file is checked (one 24 x 24 view box, paths only) and recoloured to the figure ink.
   -> assets/pictograms/<role>.svg, manifest.json

2. Photograph (stands in for a frame of the UAV camera): a public-domain aerial image of the U.S. Department of
   Agriculture, National Agriculture Imagery Program, taken from Wikimedia Commons. The licence fields and the
   checksum that Commons reports are verified before the file is kept.
   -> assets/photos/aerial_usda_naip.jpg

Both are recorded in assets/ARTWORK_ATTRIBUTION.md.      Usage:  python3 scripts/fetch_artwork.py
"""
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

MDI_VERSION = "7.4.47"
CDN = f"https://cdn.jsdelivr.net/npm/@mdi/svg@{MDI_VERSION}"
INK = "#1A1A1A"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "pictograms"
PHOTO_TITLE = "File:Headland Municipal Airport.jpg"
PHOTO_SHA1 = "b086df9a78bcd89861decedd35a54cc4240b3271"
UA = {"User-Agent": "kyber6g-paper-figures/1.0 (figures for a research paper)"}

# role -> (preferred names, search keywords)
ROLES = {
    "uav": (["quadcopter", "drone"], "quadcopter drone"),
    "camera": (["video", "camera"], "video camera"),
    "photo": (["camera"], "camera photo"),
    "image": (["image"], "image picture"),
    "film": (["filmstrip"], "filmstrip film"),
    "gnss": (["satellite-variant", "satellite-uplink"], "satellite gps"),
    "position": (["map-marker"], "map marker"),
    "antenna": (["radio-tower", "antenna"], "radio tower antenna"),
    "wifi": (["wifi"], "wifi"),
    "laptop": (["laptop"], "laptop"),
    "monitor": (["monitor-dashboard", "monitor"], "monitor dashboard"),
    "chip": (["chip", "memory"], "chip cpu"),
    "server": (["server"], "server"),
    "database": (["database"], "database"),
    "sd": (["sd", "micro-sd"], "sd card"),
    "key": (["key-variant", "key"], "key"),
    "keys": (["key-chain-variant", "key-chain"], "key chain"),
    "lock": (["lock"], "lock"),
    "unlock": (["lock-open-variant", "lock-open"], "lock open"),
    "file": (["file-document-outline", "file-document"], "file document"),
    "file_key": (["file-key"], "file key"),
    "file_lock": (["file-lock"], "file lock"),
    "shield": (["shield-check"], "shield check"),
    "shield_key": (["shield-key"], "shield key"),
    "signature": (["draw-pen", "draw", "fountain-pen-tip"], "signature pen"),
    "certificate": (["certificate"], "certificate"),
    "fingerprint": (["fingerprint"], "fingerprint"),
    "random": (["dice-multiple", "dice-5"], "dice random"),
    "refresh": (["cached", "refresh"], "refresh"),
    "ratchet": (["cog-clockwise", "rotate-right"], "rotate cog"),
    "clock": (["clock-outline"], "clock"),
    "timer": (["timer-outline", "timer"], "timer stopwatch"),
    "operator": (["account"], "account person"),
    "adversary": (["incognito"], "incognito spy"),
    "eye": (["eye"], "eye"),
    "edit": (["pencil"], "pencil edit"),
    "replay": (["repeat"], "repeat replay"),
    "downgrade": (["arrow-down-bold-circle", "arrow-down-bold"], "arrow down"),
    "mask": (["drama-masks", "domino-mask"], "mask"),
    "key_off": (["key-remove", "key-alert"], "key remove"),
    "brain": (["brain"], "brain"),
    "search": (["magnify"], "magnify search"),
    "detect": (["scan-helper", "image-filter-center-focus", "target"], "scan focus target"),
    "teach": (["school"], "school"),
    "tap": (["gesture-tap"], "gesture tap"),
    "tune": (["tune-variant", "tune"], "tune sliders"),
    "chart": (["chart-line"], "chart line"),
    "bars": (["chart-bar"], "chart bar"),
    "scale": (["scale-balance"], "scale balance"),
    "command": (["console-line", "console"], "console command"),
    "packet": (["package-variant-closed", "package-variant"], "package"),
    "counter": (["counter", "numeric"], "counter numeric"),
    "hash": (["pound"], "pound hash"),
    "cloud": (["cloud"], "cloud"),
    "cell_tower": (["access-point"], "access point"),
    "save": (["content-save"], "save"),
    "play": (["play-box", "play"], "play"),
}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read()


def normalise(svg):
    if 'viewBox="0 0 24 24"' not in svg:
        raise ValueError("not on the 24 x 24 grid")
    paths = re.findall(r'<path d="([^"]+)"\s*/>', svg)
    other = re.findall(r"<(circle|rect|line|polyline|polygon|ellipse|image|text)\b", svg)
    if not paths or other:
        raise ValueError("not a plain path pictogram")
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">'
            + "".join(f'<path fill="{INK}" d="{d}"/>' for d in paths) + "</svg>\n")


def pictograms():
    OUT.mkdir(parents=True, exist_ok=True)
    meta = {m["name"]: m for m in json.loads(get(f"{CDN}/meta.json"))}
    print(f"Material Design Icons {MDI_VERSION}: {len(meta)} pictograms in the index")
    manifest, problems = {}, []
    for role, (names, words) in ROLES.items():
        cands, how = [n for n in names if n in meta], "preferred"
        if not cands:
            want = words.split()
            scored = sorted((-sum(w in {n, *n.split("-"), *m.get("tags", []), *m.get("aliases", [])} for w in want), len(n), n)
                            for n, m in meta.items())
            cands, how = [n for s, _, n in scored[:5] if s < 0], f"search '{words}'"
        for name in cands:
            url = f"{CDN}/svg/{name}.svg"
            try:
                svg = normalise(get(url).decode())
            except Exception as e:
                problems.append(f"{role}: {name}: {e}")
                continue
            (OUT / f"{role}.svg").write_text(svg)
            manifest[role] = {"icon": name, "source": url, "selected_by": how, "sha256": hashlib.sha256(svg.encode()).hexdigest()}
            break
        else:
            problems.append(f"{role}: NO PICTOGRAM FOUND")
    (OUT / "manifest.json").write_text(json.dumps({"family": "Material Design Icons (Pictogrammers)", "version": MDI_VERSION,
                                                   "licence": "Apache-2.0", "icons": manifest}, indent=1) + "\n")
    print(f"  {len(manifest)} of {len(ROLES)} pictograms in {OUT}")
    for p in problems:
        print("  note:", p)
    return manifest, not any("NO PICTOGRAM" in p for p in problems)


def photo():
    dst = ROOT / "assets" / "photos" / "aerial_usda_naip.jpg"
    dst.parent.mkdir(parents=True, exist_ok=True)
    q = urllib.parse.urlencode({"action": "query", "format": "json", "titles": PHOTO_TITLE, "prop": "imageinfo",
                                "iiprop": "url|size|sha1|extmetadata"})
    info = list(json.loads(get("https://commons.wikimedia.org/w/api.php?" + q))["query"]["pages"].values())[0]["imageinfo"][0]
    md = {k: v.get("value", "") for k, v in info["extmetadata"].items()}
    licence_ok = md.get("LicenseShortName") == "Public domain" and md.get("Copyrighted") == "False" and md.get("AttributionRequired") == "false"
    if not licence_ok:
        raise SystemExit(f"licence of {PHOTO_TITLE} is not public domain any more: {md.get('LicenseShortName')}")
    if info["sha1"] != PHOTO_SHA1:
        raise SystemExit(f"{PHOTO_TITLE} changed on Commons (sha1 {info['sha1']})")
    data = get(info["url"])
    if hashlib.sha1(data).hexdigest() != PHOTO_SHA1:
        raise SystemExit("downloaded photo does not match the checksum Commons reports")
    dst.write_bytes(data)
    print(f"  photo {info['width']} x {info['height']} px, public domain, sha1 verified -> {dst}")
    return {"title": PHOTO_TITLE, "page": info["descriptionurl"], "author": re.sub("<[^>]+>", "", md.get("Artist", "")),
            "credit": re.sub("<[^>]+>", "", md.get("Credit", "")), "date": md.get("DateTimeOriginal", ""), "sha1": PHOTO_SHA1}


def main():
    manifest, ok = pictograms()
    ph = photo()
    lines = ["# Artwork attribution", "",
             "## Photograph", "",
             f"`assets/photos/aerial_usda_naip.jpg`: \"{ph['title'][5:-4]}\", aerial image by {ph['author']}, {ph['credit'].split('(')[0].strip()} "
             f"(NAIP), {ph['date']}. A work of the U.S. federal government, **public domain**; attribution is not required. "
             f"Source: {ph['page']} (SHA-1 `{ph['sha1']}`). In the figures a crop of it stands in for a frame of the UAV camera; "
             "it was not taken by the prototype.", "",
             "## Pictograms", "",
             f"`assets/pictograms/`: **Material Design Icons {MDI_VERSION}** by Pictogrammers (https://pictogrammers.com/library/mdi/), "
             "**Apache License 2.0**. Recoloured to the figure ink; geometry unchanged.", "",
             "| Role in the figures | Pictogram | Source |", "|---|---|---|"]
    lines += [f"| {r} | `{m['icon']}` | {m['source']} |" for r, m in manifest.items()]
    lines += ["", "## Line icons (earlier boxed version, kept in archive)", "",
              "`assets/icons/`: Tabler Icons, MIT licence; see `assets/ICON_ATTRIBUTION.md`.", "",
              "## Drawn for this paper", "",
              "`assets/illustrations/` (lattice, elliptic curve, ciphertext noise, frame crops, a synthetic sound and its ciphertext) "
              "and the pictograms `assets/pictograms/mic.svg` and `speaker.svg` are generated by `scripts/make_illustrations.py`; "
              "no third-party artwork."]
    (ROOT / "assets" / "ARTWORK_ATTRIBUTION.md").write_text("\n".join(lines) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

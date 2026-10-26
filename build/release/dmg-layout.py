#!/usr/bin/env python3
"""Write the Finder layout (.DS_Store) for the grantpin disk image.

Why this exists: `hdiutil create -srcfolder` makes an image with no .DS_Store,
so Finder opens it at the default large window with sidebar and toolbar. This
script writes a .DS_Store that makes it open as a compact, fixed 600x400 icon
view with grantpin.app and the Applications symlink side by side.

Why the output is committed: build/release/dmg/DS_Store is a small binary that
`make dmg` just copies into the staging folder as `.DS_Store`, so a release
build needs no Python and no Finder automation (AppleScript would trigger a
macOS permission dialog). Regenerate only when the layout below changes:

    pip install ds_store mac_alias
    python3 build/release/dmg-layout.py build/release/dmg/DS_Store

The keys mirror what dmgbuild (core.py) writes, which are known to work:
vSrn, bwsp, icvp, icvl on ".", and Iloc per icon. Icon positions are in the
window's coordinate space (icon centre, in points). The volume name must be
"grantpin" and the app must be named grantpin.app (see the `dmg:` target).
"""
import os
import sys

from ds_store import DSStore

WINDOW_ORIGIN = (200, 120)  # where the window opens on screen
WINDOW_SIZE = (600, 400)
ICONS = {
    "grantpin.app": (150, 190),
    "Applications": (450, 190),
}

bwsp = {
    "ShowStatusBar": False,
    "WindowBounds": "{{%d, %d}, {%d, %d}}" % (*WINDOW_ORIGIN, *WINDOW_SIZE),
    "ContainerShowSidebar": False,
    "PreviewPaneVisibility": False,
    "SidebarWidth": 0,
    "ShowTabView": False,
    "ShowToolbar": False,
    "ShowPathbar": False,
    "ShowSidebar": False,
}

icvp = {
    "viewOptionsVersion": 1,
    "backgroundType": 0,  # default (white) background; no image
    "backgroundColorRed": 1.0,
    "backgroundColorGreen": 1.0,
    "backgroundColorBlue": 1.0,
    "gridOffsetX": 0.0,
    "gridOffsetY": 0.0,
    "gridSpacing": 100.0,
    "arrangeBy": "none",
    "showIconPreview": True,
    "showItemInfo": False,
    "labelOnBottom": True,
    "textSize": 13.0,
    "iconSize": 128.0,
    "scrollPositionX": 0.0,
    "scrollPositionY": 0.0,
}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: dmg-layout.py <output DS_Store path>")
    out = sys.argv[1]
    if os.path.exists(out):
        os.remove(out)  # DSStore "w+" would otherwise reuse the old file
    with DSStore.open(out, "w+") as d:
        d["."]["vSrn"] = ("long", 1)
        d["."]["bwsp"] = bwsp
        d["."]["icvp"] = icvp
        d["."]["icvl"] = (b"type", b"icnv")
        for name, pos in ICONS.items():
            d[name]["Iloc"] = pos


if __name__ == "__main__":
    main()

"""Rebuild uptime_sync/web/static/icons-ie8.png, the icon sprite IE8 uses
(it cannot draw the inline SVG icons). Run it after changing
uptime_sync/web/icons.py:

    python tools/ie8-icons.py /tmp/ie8-icons.html

then open that file in Chrome, Edge or Firefox and save the image with the
"Save icons-ie8.png" link over uptime_sync/web/static/icons-ie8.png.
tests/test_web.py fails until the PNG has one 16px cell per icon.

The browser draws the sprite because it already rasterises SVG paths
(canvas Path2D); doing that in Python would need an imaging library.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uptime_sync.web.icons import CELL, ORDER, PATHS  # noqa: E402

COLOR = '#6b7686'   # --muted in the light theme (IE8 has no dark theme)

PAGE = """<!doctype html>
<meta charset="utf-8">
<title>icons-ie8.png</title>
<p>%(n)d icons, %(cell)dpx each. <a id="save" download="icons-ie8.png">Save icons-ie8.png</a></p>
<p><img id="out" alt="sprite" style="zoom: 4; image-rendering: pixelated; background: #fff"></p>
<script>
var paths = %(paths)s, cell = %(cell)d;
var c = document.createElement('canvas');
c.width = cell * paths.length; c.height = cell;
var g = c.getContext('2d');
g.strokeStyle = '%(color)s'; g.lineWidth = 2; g.lineCap = 'round'; g.lineJoin = 'round';
paths.forEach(function (d, i) {
  g.save(); g.translate(i * cell, 0); g.scale(cell / 24, cell / 24); g.stroke(new Path2D(d)); g.restore();
});
var url = c.toDataURL('image/png');
document.getElementById('out').src = url;
document.getElementById('save').href = url;
</script>
"""


def page():
    return PAGE % {'n': len(ORDER), 'cell': CELL, 'color': COLOR,
                   'paths': json.dumps([PATHS[n] for n in ORDER])}


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    with open(argv[1], 'w', encoding='ascii') as f:
        f.write(page())
    print('[OK] Wrote %s (%d icons). Open it in a browser and save the PNG.' % (argv[1], len(ORDER)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

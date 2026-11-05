"""Icons for the templates: {{ icon('name') }}.

Drawn for this project on a 24x24 grid, stroked with currentColor, so an
icon takes the colour of the text around it. Nothing is fetched from the
network: the agent's PC may have no internet.

IE9+ and every other browser get the inline <svg>. IE8 cannot draw SVG, so a
conditional comment (which only IE5-9 read) gives it a 16px cell of
static/icons-ie8.png instead, one cell per icon in PATHS order. Change PATHS
-> rebuild that sprite with tools/ie8-icons.py (tests/test_web.py checks
that the PNG has one cell per icon).
"""

from markupsafe import Markup

CELL = 16   # px per icon in icons-ie8.png

# A full circle is two arcs: M(cx-r) cy a r r 0 1 0 2r 0 a r r 0 1 0 -2r 0
PATHS = {
    'dashboard': 'M3 3h7v8H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 15h7v6H3z',
    'activity': 'M2 12h4l3-8 6 16 3-8h4',
    'settings': ('M4 7h8.5M17.5 7H20M12.5 7a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0'
                 'M4 17h2.5M11.5 17H20M6.5 17a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0'),
    'logs': 'M6 3h8l5 5v13H6zM14 3v5h5M9 13h7M9 17h5',
    'user': 'M8 8a4 4 0 1 0 8 0a4 4 0 1 0-8 0M4 21a8 8 0 0 1 16 0',
    'logout': 'M9 21H5V3h4M16 17l5-5-5-5M21 12H9',
    'plus': 'M12 5v14M5 12h14',
    'edit': 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
    'play': 'M7 4v16l13-8z',
    'pause': 'M8 5v14M16 5v14',
    'copy': 'M9 9h11v11H9zM5 15H4V4h11v1',
    'trash': 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6',
    'zap': 'M13 2L4 14h7l-1 8 9-12h-7z',
    'check': 'M5 12l5 5L20 7',
    'alert': 'M12 3L2 20h20zM12 9v5M12 17v.5',
    'server': 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
    'heart': 'M12 20s-8-5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 9c0 6-8 11-8 11z',
    'shield': 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4',
    'key': 'M4 12a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 12h9M18 12v3M21 12v2',
    'refresh': 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
    'download': 'M12 3v12M7 10l5 5 5-5M4 21h16',
    'back': 'M19 12H5M11 6l-6 6 6 6',
    'search': 'M4 11a7 7 0 1 0 14 0a7 7 0 1 0-14 0M16 16l5 5',
    'globe': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
    'monitor': 'M3 4h18v12H3zM8 20h8M12 16v4',
    'clock': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7v5l3 2',
    'info': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 11v5M12 8v.5',
    'list': 'M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01',
}
ORDER = list(PATHS)


def svg(name, size=16):
    """The bare <svg> (also used by tools/ie8-icons.py)."""
    return ('<svg class="ic" viewBox="0 0 24 24" width="%d" height="%d" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" '
            'focusable="false"><path d="%s"/></svg>' % (size, size, PATHS[name]))


def icon(name, size=16):
    """Inline SVG, with the IE8 sprite cell as its fallback. Decorative only:
    every icon in the UI sits next to a text label or carries a title."""
    if name not in PATHS:
        raise KeyError('no icon %r' % name)
    return Markup('<!--[if gte IE 9]><!-->%s<!--<![endif]-->'
                  '<!--[if lt IE 9]><span class="ic8 ic8-%s"></span><![endif]-->' % (svg(name, size), name))


def ie8_css():
    """The .ic8-<name> rules (sprite offsets), as app.css carries them."""
    return '\n'.join('.ic8-%s { background-position: -%dpx 0; }' % (n, i * CELL) for i, n in enumerate(ORDER))

/* Uptime Sync web UI behaviour. Templates use data-* attributes only.
 *
 * Plain ES3 on purpose: Windows 7 boxes open this page in IE8 to IE11. No
 * fetch, arrow functions, const/let, classList, closest/matches,
 * NodeList.forEach, Array.filter or textContent. Handlers are bound to each
 * element (IE8 has no addEventListener and its change event does not
 * bubble). Everything here is an extra: every page works without it.
 */
(function () {
  'use strict';

  function $all(sel) { return document.querySelectorAll ? document.querySelectorAll(sel) : []; }

  function on(el, type, fn) {
    if (el.addEventListener) {
      el.addEventListener(type, fn, false);
    } else if (el.attachEvent) {
      el.attachEvent('on' + type, function () { return fn.call(el, window.event); });
    }
  }

  function cancel(e) {
    if (e.preventDefault) { e.preventDefault(); }
    e.returnValue = false;
    return false;
  }

  function setText(el, text) {
    if (!el) { return; }
    if ('textContent' in el) { el.textContent = text; } else { el.innerText = text; }
  }

  function setHidden(el, hidden) {
    var cls = ' ' + el.className + ' ';
    var has = cls.indexOf(' hidden ') >= 0;
    if (hidden && !has) {
      el.className = (el.className + ' hidden').replace(/^\s+/, '');
    } else if (!hidden && has) {
      el.className = cls.replace(' hidden ', ' ').replace(/^\s+|\s+$/g, '');
    }
  }

  function each(list, fn) {
    for (var i = 0; i < list.length; i++) { fn(list[i]); }
  }

  // data-confirm on a button or link: ask first.
  each($all('[data-confirm]'), function (el) {
    on(el, 'click', function (e) {
      if (!window.confirm(el.getAttribute('data-confirm'))) { return cancel(e); }
      return true;
    });
  });

  // data-autosubmit on a select: submit its form on change.
  each($all('[data-autosubmit]'), function (el) {
    on(el, 'change', function () { if (el.form) { el.form.submit(); } });
  });

  each($all('[data-select-on-focus]'), function (el) {
    on(el, 'focus', function () { el.select(); });
  });

  // Password fields: an eye button that shows / hides what was typed. Added
  // here, not in the templates, so every password field gets it. Skipped
  // where the browser cannot switch an input's type once it is on the page
  // (IE8 throws): no half-working button there. app.css hides the browser's
  // own reveal eye (IE10+/Edge) and Safari's key icon, so there is one eye.
  var SVG_NS = 'http://www.w3.org/2000/svg';
  function canSwitchType() {
    if (!document.createElementNS || !document.body) { return false; }
    var t = document.createElement('input');
    var ok = false;
    try {
      t.type = 'password';
      t.className = 'hidden';
      document.body.appendChild(t);
      t.type = 'text';
      ok = t.type === 'text';
    } catch (err) {
      ok = false;
    }
    if (t.parentNode) { t.parentNode.removeChild(t); }
    return ok;
  }
  function svgEl(name, attrs) {
    var el = document.createElementNS(SVG_NS, name);
    for (var k in attrs) {
      if (attrs.hasOwnProperty(k)) { el.setAttribute(k, attrs[k]); }
    }
    return el;
  }
  function eyeIcon() {
    var svg = svgEl('svg', {viewBox: '0 0 24 24', width: '18', height: '18', fill: 'none',
      stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round',
      'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false'});
    svg.appendChild(svgEl('path', {d: 'M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z'}));
    svg.appendChild(svgEl('circle', {cx: '12', cy: '12', r: '3'}));
    var slash = svgEl('path', {d: 'M3 3l18 18', 'class': 'eye-slash'});
    svg.appendChild(slash);
    return svg;
  }
  function addReveal(input) {
    var wrap = document.createElement('span');
    wrap.className = 'pwd-wrap';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    var btn = document.createElement('button');
    btn.setAttribute('type', 'button');
    btn.className = 'pwd-eye';
    btn.setAttribute('aria-label', 'Show password');
    btn.setAttribute('title', 'Show password');
    btn.setAttribute('aria-pressed', 'false');
    btn.appendChild(eyeIcon());
    wrap.appendChild(btn);
    on(btn, 'click', function (e) {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      var label = show ? 'Hide password' : 'Show password';
      btn.setAttribute('aria-label', label);
      btn.setAttribute('title', label);
      btn.setAttribute('aria-pressed', show ? 'true' : 'false');
      wrap.className = show ? 'pwd-wrap shown' : 'pwd-wrap';
      input.focus();
      return cancel(e);   // a button inside a <label> must not re-trigger it
    });
    // Back to a password field before the form goes, so the browser does not
    // remember it as plain text.
    if (input.form) {
      on(input.form, 'submit', function () {
        if (input.type !== 'password') {
          input.type = 'password';
          wrap.className = 'pwd-wrap';
        }
      });
    }
  }
  var pwds = $all('input[type=password]');
  if (pwds.length && canSwitchType()) {
    each(pwds, function (el) { if (!el.disabled) { addReveal(el); } });
  }

  // Light/dark toggle in the top bar (and the sign-in corner). Only where the
  // browser has CSS variables: IE cannot show dark mode, so no button there.
  // The choice lives in this browser only (localStorage, read by theme.js);
  // nothing saved means the page follows the system setting.
  var THEME_KEY = 'uptime-sync-theme';
  var root = document.documentElement;
  var darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  function themeNow() {
    var t = root.getAttribute('data-theme');
    if (t === 'light' || t === 'dark') { return t; }
    return darkQuery && darkQuery.matches ? 'dark' : 'light';
  }
  function themeIcon(dark) {
    var svg = svgEl('svg', {viewBox: '0 0 24 24', width: '18', height: '18', fill: 'none',
      stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round',
      'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false'});
    if (dark) {   // sun: click for light
      svg.appendChild(svgEl('circle', {cx: '12', cy: '12', r: '4'}));
      svg.appendChild(svgEl('path', {d: 'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4' +
        'M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'}));
    } else {      // moon: click for dark
      svg.appendChild(svgEl('path', {d: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z'}));
    }
    return svg;
  }
  function drawToggle(btn) {
    var dark = themeNow() === 'dark';
    var label = dark ? 'Switch to light mode' : 'Switch to dark mode';
    while (btn.firstChild) { btn.removeChild(btn.firstChild); }
    btn.appendChild(themeIcon(dark));
    btn.setAttribute('aria-label', label);
    btn.setAttribute('title', label);
  }
  var toggles = $all('[data-theme-toggle]');
  var hasVars = window.CSS && window.CSS.supports && window.CSS.supports('--x', '0');
  if (toggles.length && hasVars && document.createElementNS) {
    each(toggles, function (btn) {
      drawToggle(btn);
      setHidden(btn, false);
      on(btn, 'click', function () {
        var next = themeNow() === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        try { window.localStorage.setItem(THEME_KEY, next); } catch (err) { /* this page only */ }
        each(toggles, drawToggle);
      });
    });
    // No saved choice: the page follows the system, so the icon must too.
    if (darkQuery) {
      var redraw = function () { each(toggles, drawToggle); };
      if (darkQuery.addEventListener) {
        darkQuery.addEventListener('change', redraw);
      } else if (darkQuery.addListener) {
        darkQuery.addListener(redraw);
      }
    }
  }

  // User menu: the name opens a dropdown (Account, Sign out). Only where the
  // dropdown CSS applies (same test as the theme toggle); elsewhere the name
  // stays a plain link to Account with Sign out beside it.
  each($all('[data-user-menu]'), function (menu) {
    var btn = $all('[data-user-menu] .menu-btn')[0];
    var list = $all('[data-user-menu] .menu')[0];
    if (!hasVars || !btn || !list || !list.getBoundingClientRect) { return; }
    var base = menu.className + ' js';
    menu.className = base;
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');
    function isOpen() { return (' ' + menu.className + ' ').indexOf(' open ') >= 0; }
    function setOpen(open) {
      menu.className = open ? base + ' open' : base;
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      // Right-aligned under the name, unless that runs off the left edge
      // (narrow window: the top bar wraps and the name starts a line).
      if (open && list.getBoundingClientRect().left < 0) { menu.className += ' align-left'; }
    }
    on(btn, 'click', function (e) {
      setOpen(!isOpen());
      return cancel(e);
    });
    on(document, 'click', function (e) {
      var t = e.target || e.srcElement;
      if (isOpen() && t && !menu.contains(t)) { setOpen(false); }
    });
    on(document, 'keydown', function (e) {
      if (isOpen() && e.keyCode === 27) { setOpen(false); btn.focus(); }
    });
  });

  // Monitor form: show only the fields that apply to the chosen type, and
  // swap placeholders from data-ph="PING=...|DNS=...|TCP=..." (keyed by the
  // type's first word). IE8/9 have no placeholder; the hints say the same.
  var typeSelect = $all('[data-type-select]')[0];
  function placeholderFor(spec, first) {
    var pairs = spec.split('|');
    for (var i = 0; i < pairs.length; i++) {
      var eq = pairs[i].indexOf('=');
      if (eq > 0 && pairs[i].substring(0, eq) === first) { return pairs[i].substring(eq + 1); }
    }
    return null;
  }
  function applyType() {
    var t = typeSelect.value;
    var first = t.split(' ')[0];
    each($all('[data-for-types]'), function (el) {
      var types = ' ' + el.getAttribute('data-for-types') + ' ';
      setHidden(el, types.indexOf(' ' + first + ' ') < 0 && types.indexOf(' ' + t + ' ') < 0);
    });
    each($all('[data-ph]'), function (el) {
      var ph = placeholderFor(el.getAttribute('data-ph'), first);
      if (ph !== null) { el.setAttribute('placeholder', ph); }
    });
  }
  if (typeSelect) { on(typeSelect, 'change', applyType); applyType(); }

  // Settings: editing a server URL selects its radio (data-selects = the
  // radio's id), so the URL just typed is the one that gets used.
  each($all('[data-selects]'), function (el) {
    on(el, 'focus', function () {
      var radio = document.getElementById(el.getAttribute('data-selects'));
      if (radio && !el.disabled) { radio.checked = true; }
    });
  });

  // Toasts (base.html): a close button on each, and ok / info notices fade
  // out after TOAST_MS, paused while the pointer or keyboard focus is on
  // them. Warnings (form errors, refusals) stay until closed: they say what
  // to fix. Without this script every toast just stays.
  var TOAST_MS = 6000;
  function setupToast(t) {
    var x = document.createElement('button');
    var timer = null;
    var gone = false;
    x.type = 'button';
    x.className = 'toast-x';
    x.title = 'Dismiss';
    x.setAttribute('aria-label', 'Dismiss');
    setText(x, '\u00d7');   // multiplication sign
    t.appendChild(x);
    function stop() { if (timer) { window.clearTimeout(timer); timer = null; } }
    function remove() {
      if (gone) { return; }
      gone = true;
      stop();
      t.className += ' leaving';
      window.setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, 220);
    }
    on(x, 'click', remove);
    if ((' ' + t.className + ' ').indexOf(' warn ') >= 0) { return; }
    function start() { stop(); if (!gone) { timer = window.setTimeout(remove, TOAST_MS); } }
    on(t, 'mouseover', stop);
    on(t, 'mouseout', start);
    on(x, 'focus', stop);
    on(x, 'blur', start);
    start();
  }
  each($all('[data-toasts] .toast'), setupToast);

  // Logs: a message longer than 3 lines (data-more = the lines past 3, set
  // by the server) shows its first lines and a button for the rest, so one
  // traceback does not push the page down. Without this script it shows whole.
  each($all('pre.msg[data-more]'), function (pre) {
    var extra = pre.getAttribute('data-more');
    var btn = document.createElement('button');
    var open = false;
    btn.type = 'button';
    btn.className = 'more';
    function draw() {
      pre.className = open ? 'msg' : 'msg folded';
      setText(btn, open ? 'Show less' : extra + ' more line' + (extra === '1' ? '' : 's'));
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    on(btn, 'click', function (e) { open = !open; draw(); return cancel(e); });
    pre.parentNode.insertBefore(btn, pre.nextSibling);
    draw();
  });

  // Dashboard: refresh from /api/status every 15 s.
  var tiles = $all('[data-status-url]')[0];
  if (!tiles || !window.XMLHttpRequest || !window.JSON) { return; }
  var url = tiles.getAttribute('data-status-url');

  function field(name) { return $all('[data-field="' + name + '"]')[0]; }
  function cell(text, cls, label) {
    var td = document.createElement('td');
    if (cls) { td.className = cls; }
    if (label) { td.setAttribute('data-label', label); }
    setText(td, text);
    return td;
  }
  function render(st) {
    var i, m, tiles = $all('[data-tile]');
    // The server decides each tile's colour (views.tones); just apply it.
    for (i = 0; i < tiles.length; i++) {
      var tone = st.tones && st.tones[tiles[i].getAttribute('data-tile')];
      if (tone) { tiles[i].className = 'tile tone-' + tone; }
    }
    // The words come from the server (views.tile_text), the same ones the
    // first paint used.
    var names = ['engine', 'engine_sub', 'counts', 'heartbeat', 'heartbeat_sub', 'signing', 'signing_sub'];
    for (i = 0; i < names.length; i++) {
      if (st.text && st.text[names[i]] !== undefined) { setText(field(names[i]), st.text[names[i]]); }
    }

    var body = $all('[data-rows]')[0];
    if (!body) { return; }
    // IE9 and older cannot set innerHTML on a tbody: remove rows one by one.
    while (body.firstChild) { body.removeChild(body.firstChild); }
    if (!st.monitors.length) {
      var empty = document.createElement('tr');
      var etd = cell('No monitors yet.', 'empty');
      etd.setAttribute('colSpan', '7');
      empty.appendChild(etd);
      body.appendChild(empty);
      return;
    }
    for (i = 0; i < st.monitors.length; i++) {
      m = st.monitors[i];
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      var pill = document.createElement('span');
      td.className = 'lead';
      pill.className = 'pill ' + m.state;
      setText(pill, m.state);
      td.appendChild(pill);
      tr.appendChild(td);
      tr.appendChild(cell(m.name, 'title'));
      tr.appendChild(cell(m.type, '', 'Type'));
      tr.appendChild(cell(m.target, 'mono', 'Target'));
      tr.appendChild(cell(m.ms === null || m.ms === undefined ? '-' : m.ms + ' ms', 'num', 'Response'));
      tr.appendChild(cell(m.uptime === null || m.uptime === undefined ? '-' : m.uptime + '%', 'num', 'Uptime'));
      tr.appendChild(cell(m.checked_at ? m.checked_at.slice(11, 19) : '-', 'muted', 'Checked'));
      body.appendChild(tr);
    }
  }
  function unreachable() { setText(field('engine_sub'), 'web UI cannot reach the status file'); }
  function refresh() {
    var xhr = new XMLHttpRequest();
    try {
      // The timestamp defeats IE's habit of caching XHR GETs.
      xhr.open('GET', url + (url.indexOf('?') < 0 ? '?' : '&') + '_=' + new Date().getTime(), true);
      xhr.setRequestHeader('Accept', 'application/json');
    } catch (err) {
      unreachable();   // old IE throws "Access is denied" here instead of failing the request
      return;
    }
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) { return; }
      if (xhr.status === 401) { window.location.reload(); return; }
      var st = null;
      if (xhr.status === 200) {
        try { st = JSON.parse(xhr.responseText); } catch (err) { st = null; }
      }
      if (st) { render(st); } else { unreachable(); }
    };
    try { xhr.send(null); } catch (err) { unreachable(); }
  }
  // No refresh at load: the page was just rendered from the same data.
  window.setInterval(refresh, 15000);
})();

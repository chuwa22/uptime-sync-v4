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

  // Dashboard: refresh from /api/status every 15 s.
  var tiles = $all('[data-status-url]')[0];
  if (!tiles || !window.XMLHttpRequest || !window.JSON) { return; }
  var url = tiles.getAttribute('data-status-url');

  function field(name) { return $all('[data-field="' + name + '"]')[0]; }
  function ago(epoch, now) {
    if (!epoch) { return 'never'; }
    var s = Math.max(0, Math.round(now - epoch));
    return s < 90 ? s + ' s ago' : Math.round(s / 60) + ' min ago';
  }
  function cell(text, cls) {
    var td = document.createElement('td');
    if (cls) { td.className = cls; }
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
    setText(field('counts'), st.counts.up + ' / ' + st.counts.enabled);
    setText(field('engine'), st.engine.running ? 'Running' : 'Stopped');
    setText(field('engine_sub'), 'last cycle ' + (st.engine.updated_at ? st.engine.updated_at.slice(11, 19) : '-'));
    var hb = st.heartbeat;
    setText(field('heartbeat'), !hb.enabled ? 'Off' : hb.failures ? 'Failing' : hb.error ? 'Error' :
      hb.last_ok ? 'OK' : 'Waiting');
    setText(field('heartbeat_sub'), !hb.enabled ? 'reporting disabled' :
      (hb.error ? hb.error + ' - ' : '') + 'last OK ' + ago(hb.last_ok, st.now));
    setText(field('signing'), st.signing.state);
    setText(field('signing_sub'), st.signing.since ? 'since ' + st.signing.since.slice(0, 10) : '');

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
      pill.className = 'pill ' + m.state;
      setText(pill, m.state);
      td.appendChild(pill);
      tr.appendChild(td);
      tr.appendChild(cell(m.name));
      tr.appendChild(cell(m.type));
      tr.appendChild(cell(m.target, 'mono'));
      tr.appendChild(cell(m.ms === null || m.ms === undefined ? '-' : m.ms + ' ms', 'num'));
      tr.appendChild(cell(m.uptime === null || m.uptime === undefined ? '-' : m.uptime + '%', 'num'));
      tr.appendChild(cell(m.checked_at ? m.checked_at.slice(11, 19) : '-', 'muted'));
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
  refresh();
  window.setInterval(refresh, 15000);
})();

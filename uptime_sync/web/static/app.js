/* Uptime Sync web UI behaviour. Templates use data-* attributes only. */
(function () {
  'use strict';

  // data-confirm on a button or link: ask first.
  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-confirm]');
    if (el && !window.confirm(el.getAttribute('data-confirm'))) {
      e.preventDefault();
    }
  });

  // data-autosubmit on a select: submit its form on change.
  document.addEventListener('change', function (e) {
    if (e.target.matches('[data-autosubmit]')) { e.target.form.submit(); }
  });

  document.addEventListener('focusin', function (e) {
    if (e.target.matches('[data-select-on-focus]')) { e.target.select(); }
  });

  // Monitor form: show only the fields that apply to the chosen type.
  var typeSelect = document.querySelector('[data-type-select]');
  function applyType() {
    var t = typeSelect.value;
    document.querySelectorAll('[data-for-types]').forEach(function (el) {
      var types = el.getAttribute('data-for-types').split(' ');
      el.classList.toggle('hidden', types.indexOf(t.split(' ')[0]) < 0 && types.indexOf(t) < 0);
    });
  }
  if (typeSelect) { typeSelect.addEventListener('change', applyType); applyType(); }

  // Dashboard: refresh from /api/status every 15 s.
  var tiles = document.querySelector('[data-status-url]');
  if (!tiles) { return; }
  var url = tiles.getAttribute('data-status-url');

  function setText(name, text) {
    var el = document.querySelector('[data-field="' + name + '"]');
    if (el) { el.textContent = text; }
  }
  function ago(epoch, now) {
    if (!epoch) { return 'never'; }
    var s = Math.max(0, Math.round(now - epoch));
    return s < 90 ? s + ' s ago' : Math.round(s / 60) + ' min ago';
  }
  function cell(text, cls) {
    var td = document.createElement('td');
    if (cls) { td.className = cls; }
    td.textContent = text;
    return td;
  }
  function render(st) {
    var enabled = st.monitors.filter(function (m) { return m.enabled; });
    var up = enabled.filter(function (m) { return m.state === 'up'; });
    setText('counts', up.length + ' / ' + enabled.length);
    setText('engine', st.engine.running ? 'Running' : 'Stopped');
    setText('engine_sub', 'last cycle ' + (st.engine.updated_at ? st.engine.updated_at.slice(11, 19) : '-'));
    var hb = st.heartbeat;
    setText('heartbeat', !hb.enabled ? 'Off' : hb.failures ? 'Failing' : hb.last_ok ? 'OK' : 'Waiting');
    setText('heartbeat_sub', !hb.enabled ? 'reporting disabled' :
      (hb.error ? hb.error + ' - ' : '') + 'last OK ' + ago(hb.last_ok, st.now));
    setText('signing', st.signing.state);
    setText('signing_sub', st.signing.since ? 'since ' + st.signing.since.slice(0, 10) : '');

    var body = document.querySelector('[data-rows]');
    if (!body || !st.monitors.length) { return; }
    var frag = document.createDocumentFragment();
    st.monitors.forEach(function (m) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      var pill = document.createElement('span');
      pill.className = 'pill ' + m.state;
      pill.textContent = m.state;
      td.appendChild(pill);
      tr.appendChild(td);
      tr.appendChild(cell(m.name));
      tr.appendChild(cell(m.type));
      tr.appendChild(cell(m.target, 'mono'));
      tr.appendChild(cell(m.ms === null || m.ms === undefined ? '-' : m.ms + ' ms', 'num'));
      tr.appendChild(cell(m.uptime === null ? '-' : m.uptime + '%', 'num'));
      tr.appendChild(cell(m.checked_at ? m.checked_at.slice(11, 19) : '-', 'muted'));
      frag.appendChild(tr);
    });
    body.replaceChildren ? body.replaceChildren(frag) : (body.innerHTML = '', body.appendChild(frag));
  }
  function refresh() {
    fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { if (r.status === 401) { window.location.reload(); } return r.json(); })
      .then(render)
      .catch(function () { setText('engine_sub', 'web UI cannot reach the status file'); });
  }
  refresh();
  setInterval(refresh, 15000);
})();

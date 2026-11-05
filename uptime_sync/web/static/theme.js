/* Loaded in <head>, before the page is drawn: apply the light/dark choice
 * saved by the toggle (app.js), so the page does not flash the other theme.
 * No choice saved = follow the system (app.css prefers-color-scheme).
 * ES3, and storage may be missing or blocked: every failure means "system". */
(function () {
  try {
    var t = window.localStorage && window.localStorage.getItem('uptime-sync-theme');
    if (t === 'light' || t === 'dark') { document.documentElement.setAttribute('data-theme', t); }
  } catch (err) {
    return;
  }
}());

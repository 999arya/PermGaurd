"""HTTP lifecycle for the original dashboard, rendered by Flask."""
from collections import OrderedDict
import secrets
import threading
import time
from pathlib import Path
from flask import request, session, Response, abort, current_app
from itsdangerous import BadSignature
from .webstate import dump_state, load_state
from .webui import Renderer, State, Rerun, _active

ROOT = Path(__file__).resolve().parents[1]
_sessions = OrderedDict()
_sessions_lock = threading.Lock()
_source = compile((ROOT / 'dashboard.py').read_text(encoding='utf-8-sig'), str(ROOT / 'dashboard.py'), 'exec')


def render_dashboard():
    import json
    session.setdefault('dashboard_id', secrets.token_urlsafe(24))
    session.setdefault('csrf', secrets.token_urlsafe(24))
    if request.method == 'POST' and not secrets.compare_digest(request.form.get('_csrf', ''), session['csrf']):
        abort(403)
    identity = session['dashboard_id']
    hosted = current_app.config['HOSTED']
    with _sessions_lock:
        now = time.monotonic()
        for key in list(_sessions):
            if now - _sessions[key][2] > 3600:
                del _sessions[key]
        if identity not in _sessions:
            if len(_sessions) >= 16:
                _sessions.popitem(last=False)
            _sessions[identity] = [State(), threading.Lock(), now]
        entry = _sessions[identity]
        entry[2] = now
        _sessions.move_to_end(identity)
    state, lock, _ = entry
    if hosted:
        snapshot = request.form.get('_snapshot', '')
        try:
            state = State(load_state(snapshot, current_app.secret_key, identity)) if snapshot else State()
        except (BadSignature, ValueError):
            abort(400, description='Invalid or expired dashboard state. Reload the page.')
    with lock:
        values = json.loads(request.form.get('_values', '{}'))
        if not isinstance(values, dict):abort(400)
        uploads = {key: [(upload.filename, upload.read()) for upload in request.files.getlist(key) if upload.filename] for key in request.files}
        clear = request.form.get('_clear_upload')
        if clear: uploads[clear] = []
        event = request.form.get('_event', '')
        for attempt in range(4):
            renderer = Renderer(state, values, uploads, event)
            token = _active.set(renderer)
            try:
                exec(_source, {'__file__':str(ROOT / 'dashboard.py'), '__name__':'permguard_dashboard'})
                break
            except Rerun:
                event, values, uploads = '', {}, {}
            finally:
                _active.reset(token)
        else:
            abort(500)
        content = renderer.root.render()
        sidebar = renderer.sidebar.render()
        snapshot = dump_state(state, current_app.secret_key, identity) if hosted else ''
    page = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PermGuard</title><link rel="stylesheet" href="/_ui/runtime.css"><script src="/_ui/plotly.js" defer></script><script src="/_ui/runtime.js" defer></script></head><body><form id="dashboard" enctype="multipart/form-data"><input type="hidden" id="csrf" value="'''+session['csrf']+'''">'''+sidebar+'''<button type="button" id="sidebar-toggle" aria-label="Open sidebar">›</button><main data-testid="stMain"><div data-testid="stAppViewContainer"><div class="block-container"><div class="ui-root">'''+content+'''</div></div></div></main></form><div id="busy" hidden role="status">Running PermGuard analysis…</div></body></html>'''
    page = page.replace('<input type="hidden" id="csrf"', '<input type="hidden" id="snapshot" value="'+snapshot+'"><input type="hidden" id="csrf"')
    if hosted:
        page = page.replace('200MB per file', '4MB per request (hosted limit)')
        page = page.replace('<form id="dashboard"', '<form data-hosted="true" id="dashboard"')
    return Response(page, mimetype='text/html', headers={'Cache-Control':'no-store'})

"""The Flask renderer preserves original controls, events and report views."""
import hashlib
import json
import re
from pathlib import Path
import pytest
from app import create_app
from src.webruntime import _sessions


def uid(label):
    return 'w_' + hashlib.sha256(label.encode()).hexdigest()[:16]


@pytest.fixture
def client(tmp_path):
    app=create_app({'TESTING':True,'HOSTED':False,'DATABASE':str(tmp_path/'scans.db'),'CACHE_DIR':str(tmp_path/'cache')})
    return app.test_client()


def hidden(response,name):
    return re.search('id="'+name+'" value="([^"]*)"',response.get_data(as_text=True)).group(1)


def action(client,response,event='',values=None):
    return client.post('/',data={'_csrf':hidden(response,'csrf'),'_snapshot':hidden(response,'snapshot'),'_event':event,'_values':json.dumps(values or {})})


def test_original_form_and_scan(client):
    page=client.get('/')
    assert page.status_code==200
    body=page.get_data(as_text=True)
    for label in ['START A PRIVATE SCAN','Analyze your APK','Drop Your APK Here','Or scan a local folder of APKs','Calculator','Flashlight','Navigation','Voice Recorder','Photo Editor','App Category','Mildly critical','Medium','Organisation Policy','Analyze Permissions']:
        assert label in body
    assert '<option value="Medium" selected>' in body
    chosen=action(client,page,'smp_flashlight_overprivileged.apk')
    assert 'Selected sample:' in chosen.get_data(as_text=True)
    assert 'Risk score &mdash;' not in chosen.get_data(as_text=True)
    result=action(client,chosen,uid('Analyze Permissions'))
    body=result.get_data(as_text=True)
    assert 'Summary' in body and 'Recommended Actions' in body and 'data-plot=' in body
    assert 'Unexpected error' not in body
    prepared=action(client,result,'ov_gen_pdf')
    assert 'data:application/pdf;base64,JVBER' in prepared.get_data(as_text=True)
    reset=action(client,prepared,uid('New scan'))
    assert 'Analyze your APK' in reset.get_data(as_text=True)


def test_all_original_views(client):
    page=action(client,client.get('/'),'smp_calculator.apk')
    page=action(client,page,uid('Analyze Permissions'))
    with client.session_transaction() as session:
        state=_sessions[session['dashboard_id']][0]
    for section in ['Permission Inventory','Policy Analysis','Risk Analysis','Remediation','Comparison','Export']:
        state['tool_page']=section
        response=client.get('/')
        assert response.status_code==200
        assert 'Unexpected error' not in response.get_data(as_text=True)


def test_csrf_and_upload_limit(client):
    assert client.post('/',data={}).status_code==403
    client.application.config['MAX_CONTENT_LENGTH']=2
    assert client.post('/',data=b'123').status_code==413
    assert client.get('/dashboard.py').status_code==404
    assert client.get('/api/health').json=={'status':'ok'}


def test_hosted_state_survives_worker_change(tmp_path,monkeypatch):
    monkeypatch.setenv('PERMGUARD_SESSION_SECRET','test-secret-at-least-thirty-two-characters')
    app=create_app({'TESTING':True,'HOSTED':True})
    c=app.test_client()
    initial=c.get('/')
    chosen=action(c,initial,'smp_flashlight_overprivileged.apk')
    _sessions.clear()
    result=action(c,chosen,uid('Analyze Permissions'))
    assert 'Recommended Actions' in result.get_data(as_text=True)
    _sessions.clear()
    pdf=action(c,result,'ov_gen_pdf')
    assert 'data:application/pdf;base64,JVBER' in pdf.get_data(as_text=True)
    bad=c.post('/',data={'_csrf':hidden(pdf,'csrf'),'_snapshot':'tampered'})
    assert bad.status_code==400


def test_no_streamlit_import():
    root=Path(__file__).resolve().parents[1]
    source=(root/'dashboard.py').read_text(encoding='utf8')
    assert 'import streamlit' not in source
    assert 'from src import webui as st' in source


def test_batch_upload_and_saved_mobsf(client):
    import io
    root=Path(__file__).resolve().parents[1]
    page=client.get('/')
    response=client.post('/',data={'_csrf':hidden(page,'csrf'),'_event':uid('Analyze Permissions'),
        '_values':json.dumps({uid('Mode'):'Add MobSF cross-check (optional)',uid('Use bundled sample MobSF reports when the APK matches'):True}),
        'apk_uploader':[(io.BytesIO((root/'data/sampleapps/calculator.apk').read_bytes()),'calculator.apk'),(io.BytesIO((root/'data/sampleapps/flashlight_overprivileged.apk').read_bytes()),'flashlight_overprivileged.apk')]})
    body=response.get_data(as_text=True)
    assert 'Phone safety score' in body and 'Evidence' in body
    assert 'Unexpected error' not in body
    flashlight=action(client,response,values={uid('Viewing app'):'1'})
    assert 'Permission agreement' in flashlight.get_data(as_text=True)


def test_contact_form_keeps_original_validation(client):
    page=client.get('/')
    invalid=action(client,page,uid('Send Message'),{uid('Name'):'',uid('Email'):'bad',uid('Message'):'Hi'})
    assert 'Enter your name, a valid email address, and a message.' in invalid.get_data(as_text=True)
    valid=action(client,invalid,uid('Send Message'),{uid('Name'):'Tester',uid('Email'):'test@example.com',uid('Message'):'Hello'})
    assert 'Your message has not been sent.' in valid.get_data(as_text=True)


def test_hosted_requires_secret(monkeypatch):
    monkeypatch.delenv('PERMGUARD_SESSION_SECRET',raising=False)
    c=create_app({'TESTING':True,'HOSTED':True}).test_client()
    assert c.get('/').status_code==503
    assert c.get('/api/health').status_code==503

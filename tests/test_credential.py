import io
import json
import sqlite3
import zipfile
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from app import credential, main
from app.engine import evaluate


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', str(tmp_path / 'credential.sqlite'))
    return TestClient(main.app)


def bundle(clean):
    return credential.build(clean)


def test_seal_is_reproducible_across_generations(clean):
    first, second = bundle(clean), credential.build(evaluate({'dataset': 'clean'}))
    # make_manifest 的生成时刻与耗时每次都不同，但不得影响封存边界。
    assert first['evidence']['seal'] == second['evidence']['seal']
    assert first['zip'] == second['zip']


def test_seal_ignores_review_revision_and_display_order(clean):
    seal = bundle(clean)['seal']
    shuffled = deepcopy(clean)
    shuffled['windows'] = list(reversed(shuffled['windows']))
    shuffled['selected_results'] = list(reversed(shuffled['selected_results']))
    shuffled['records'] = list(reversed(shuffled['records']))
    shuffled['deviations'] = list(reversed(shuffled['deviations']))
    shuffled['revision'], shuffled['status'] = 7, '已复核'
    assert bundle(shuffled)['seal'] == seal


def test_bundle_carries_records_and_verification_basis(clean):
    archive = zipfile.ZipFile(io.BytesIO(bundle(clean)['zip']))
    assert set(archive.namelist()) >= {'manifest.json', 'evidence.json', 'checksums.json',
                                       'source.csv', 'verify.py', 'SEAL.md'}
    evidence = json.loads(archive.read('evidence.json'))
    assert archive.read('source.csv') == credential.source_bytes(clean)
    assert len(evidence['visits']) == 40
    assert evidence['source_rows']
    visit = next(v for v in evidence['visits'] if v['subject'] == '00001' and v['visit'] == 'V1')
    assert visit['result']['primary_line'] == 2 and visit['result']['selected_line'] == 4
    assert visit['window'] == {'start_day': 5, 'end_day': 10}
    assert [ref['role'] for ref in visit['sources']] == ['primary', 'selected']
    assert credential.verify_bundle(bundle(clean)['zip'])['ok']


def test_every_input_line_is_retained(sample):
    ledger = bundle(sample)['evidence']['source_rows']
    assert [row['line'] for row in ledger] == list(range(2, 53))
    kinds = {row['kind'] for row in ledger}
    assert {'data', 'rejected', 'duplicate', 'repeated_header', 'blank'} <= kinds
    visit = next(v for v in bundle(sample)['evidence']['visits']
                 if v['subject'] == '00020' and v['visit'] == 'V2')
    assert visit['status'] == 'MISSING_PRIMARY'


def test_tampered_source_row_is_detected(clean):
    document = bundle(clean)
    files = dict(document['files'])
    files['source.csv'] = files['source.csv'].replace(b'2026-10-08T08:00:00+08:00',
                                                      b'2026-10-12T08:00:00+08:00', 1)
    tampered = credential.pack(files)
    report = credential.verify_bundle(tampered)
    assert not report['ok'] and report['blocked']
    assert any('source.csv 摘要不符' in item for item in report['errors'])
    assert any('责任行内容不符: 00001 V1 第2行' in item for item in report['errors'])


def test_missing_source_row_is_detected(clean):
    document = bundle(clean)
    files = dict(document['files'])
    files['source.csv'] = b'\n'.join(files['source.csv'].splitlines()[:10]) + b'\n'
    report = credential.verify_bundle(credential.pack(files))
    assert not report['ok']
    assert any('原始行缺失' in item for item in report['errors'])


def test_forged_result_breaks_integrity(clean):
    document = bundle(clean)
    evidence = deepcopy(document['evidence'])
    visit = next(v for v in evidence['visits'] if v['subject'] == '00001' and v['visit'] == 'V1')
    visit['result']['value_mg_dl'] = '999'
    visit['digest'] = credential.sha256_hex(
        credential.canonical({k: v for k, v in visit.items() if k != 'digest'}))
    evidence['seal'] = credential.seal_of(evidence)
    forged = dict(document['files'], **{'evidence.json': credential.pretty(evidence)})
    # 篡改并重签 evidence 后，manifest 与 checksums 的 seal/摘要必须对不上。
    report = credential.verify_bundle(credential.pack(forged))
    assert not report['ok'] and report['blocked']
    assert any('seal' in item for item in report['errors'])
    assert any('摘要不符' in item for item in report['errors'])


def test_changed_window_points_to_subject_visit(clean):
    changed = deepcopy(clean)
    changed['windows'] = deepcopy(clean['windows'])
    for row in changed['windows']:
        if row['id'] == '00001-V1':
            row['start_day'], row['end_day'] = 6, 11
    report = credential.verify_bundle(bundle(clean)['zip'], expected=changed)
    assert not report['ok'] and report['blocked']
    assert report['changed'] == [{'subject': '00001', 'visit': 'V1', 'fields': ['window']}]
    assert '00001 V1' in credential.changed_visits_text(report)


def test_changed_selection_points_to_subject_visit(clean):
    changed = deepcopy(clean)
    changed['selected_results'] = deepcopy(clean['selected_results'])
    selected = next(r for r in changed['selected_results'] if r['primary_id'] == '00001-V1')
    selected['value_mg_dl'] = '999'
    report = credential.verify_bundle(bundle(clean)['zip'], expected=changed)
    assert not report['ok']
    assert report['changed'][0]['subject'] == '00001'
    assert report['changed'][0]['visit'] == 'V1'
    assert 'result' in report['changed'][0]['fields']


def test_standalone_script_self_checks_and_compares(clean, sample, tmp_path):
    import subprocess
    import sys

    document = bundle(clean)
    target = tmp_path / 'clean'
    target.mkdir()
    for name, payload in document['files'].items():
        (target / name).write_bytes(payload)
    script = target / 'verify.py'
    own = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert own.returncode == 0, own.stdout
    other = tmp_path / 'dirty.zip'
    other.write_bytes(bundle(sample)['zip'])
    cross = subprocess.run([sys.executable, str(script), str(target), str(other)],
                           capture_output=True, text=True)
    assert cross.returncode == 1
    result = json.loads(cross.stdout)
    assert {item['subject'] for item in result['changed']} >= {'00001', '00020'}


def test_export_blocks_changed_results_and_keeps_old_credential(client, tmp_path):
    run = client.post('/api/runs', json={'dataset': 'clean'}).json()
    run_id = run['manifest']['run_id']
    first = client.get(f'/api/export/{run_id}')
    assert first.status_code == 200
    seal = first.headers['X-Credential-Seal']

    path = main.DB_PATH
    con = sqlite3.connect(path)
    result = json.loads(con.execute('SELECT result FROM runs WHERE id=?', (run_id,)).fetchone()[0])
    result['selected_results'][0]['value_mg_dl'] = '999'
    con.execute('UPDATE runs SET result=? WHERE id=?',
                (json.dumps(result, ensure_ascii=False), run_id))
    con.commit()
    con.close()

    blocked = client.get(f'/api/export/{run_id}')
    assert blocked.status_code == 409
    body = blocked.json()
    assert body['code'] == 'CREDENTIAL_BLOCKED' and body['blocked']
    assert body['previous_seal'] == seal
    assert body['changed'][0]['subject'] == '00001' and body['changed'][0]['visit'] == 'V1'
    assert '00001 V1' in body['detail']

    status = client.get(f'/api/credential/{run_id}').json()
    assert status['current'] == seal
    assert client.get(f'/api/credential/{run_id}/{seal}').status_code == 200


def test_export_is_byte_identical_when_content_unchanged(client):
    run = client.post('/api/runs', json={'dataset': 'clean'}).json()
    run_id = run['manifest']['run_id']
    first = client.get(f'/api/export/{run_id}')
    client.post(f'/api/runs/{run_id}/review', json={'revision': 1})
    second = client.get(f'/api/export/{run_id}')
    assert second.status_code == 200
    assert second.content == first.content
    assert second.headers['X-Credential-Seal'] == first.headers['X-Credential-Seal']


def test_replace_failure_keeps_old_credential(client):
    clean = client.post('/api/runs', json={'dataset': 'clean'}).json()
    dirty = client.post('/api/runs', json={'dataset': 'dirty'}).json()
    clean_id, dirty_id = clean['manifest']['run_id'], dirty['manifest']['run_id']
    dirty_zip = client.get(f'/api/export/{dirty_id}').content
    dirty_seal = client.get(f'/api/credential/{dirty_id}').json()['current']

    rejected = client.post(f'/api/credential/{dirty_id}/replace',
                           content=client.get(f'/api/export/{clean_id}').content)
    assert rejected.status_code == 409
    assert rejected.json()['previous_seal'] == dirty_seal
    assert rejected.json()['changed']
    status = client.get(f'/api/credential/{dirty_id}').json()
    assert status['current'] == dirty_seal
    assert len(status['history']) == 1
    assert client.get(f'/api/credential/{dirty_id}/{dirty_seal}').content == dirty_zip

    accepted = client.post(f'/api/credential/{dirty_id}/replace', content=dirty_zip)
    assert accepted.status_code == 200
    assert accepted.json()['seal'] == dirty_seal


def test_verify_endpoint_reports_changed_visits(client):
    clean = client.post('/api/runs', json={'dataset': 'clean'}).json()
    dirty = client.post('/api/runs', json={'dataset': 'dirty'}).json()
    package = client.get(f"/api/export/{clean['manifest']['run_id']}").content
    report = client.post(f"/api/credential/verify?run_id={dirty['manifest']['run_id']}",
                         content=package).json()
    assert report['ok'] is False and report['blocked'] is True
    assert {item['subject'] for item in report['changed']} >= {'00001', '00020'}
    assert '00001 V1' in report['changed_text']


def test_legacy_encoding_credential_keeps_original_bytes():
    legacy = evaluate({'dataset': 'legacy'})
    package = bundle(legacy)['zip']
    archive = zipfile.ZipFile(io.BytesIO(package))
    assert archive.read('source.csv') == credential.source_bytes(legacy)
    assert credential.verify_bundle(package)['ok']

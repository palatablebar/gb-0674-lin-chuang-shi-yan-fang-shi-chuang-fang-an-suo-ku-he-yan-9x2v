import hashlib
import json


def freeze(state):
    basis = {'selected': state['selected_results'], 'windows': state['windows'],
             'deviations': state['deviations']}
    return {'status': '可冻结' if state['balance']['status'] == '可锁库' else '待处理',
            'seal': hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest(),
            'subjects': len(state['context']['subjects']),
            'results': len(state['selected_results'])}


STATUS_LABELS = {'SETTLED': '已采信', 'MISSING_PRIMARY': '漏访', 'DUPLICATE_PRIMARY': '首次重复',
                 'WINDOW_LATE': '窗外（晚）', 'WINDOW_EARLY': '窗外（早）'}


def rows(state, evidence=None):
    if evidence is None:
        from app.credential import build
        evidence = build(state, with_files=False)['evidence']
    visits = evidence.get('visits') or []
    return [{
        'subject': visit['subject'],
        'visit': visit['visit'],
        'status': STATUS_LABELS.get(visit['status'], visit['status']),
        'protocol': visit.get('protocol') or '',
        'window': ('[%s,%s)' % (visit['window']['start_day'], visit['window']['end_day'])
                   if visit.get('window') else '—'),
        'day': visit.get('day') if visit.get('day') is not None else '—',
        'id': (visit.get('result') or {}).get('id', ''),
        'value_mg_dl': (visit.get('result') or {}).get('value_mg_dl', ''),
        'primary_line': (visit.get('result') or {}).get('primary_line', ''),
        'selected_line': (visit.get('result') or {}).get('selected_line', ''),
        'line': ','.join(str(line) for line in (visit.get('lines') or [])),
        'blocking': ','.join(visit.get('blocking') or []),
    } for visit in visits]


def apply(state):
    from app.credential import build
    state['archive'] = freeze(state)
    document = build(state, with_files=False)
    # 只暴露封存编号与边界说明；完整凭证在下载/替换时构造。
    state['credential'] = {'seal': document['seal'],
                           'credential_id': document['credential_id'],
                           'algorithm': 'sha256',
                           'seal_includes': document['manifest']['seal_includes'],
                           'seal_excludes': document['manifest']['seal_excludes']}
    state['views']['archive'] = {'title': '冻结清单', 'rows': rows(state, document['evidence']),
                                 'metrics': {'受试者': state['archive']['subjects'],
                                             '结果': state['archive']['results'],
                                             '状态': state['archive']['status']}}

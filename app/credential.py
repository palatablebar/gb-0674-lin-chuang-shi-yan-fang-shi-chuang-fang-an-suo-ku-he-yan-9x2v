"""冻结凭证的内容定义、封存边界与离线校验。

封存边界（seal boundary）固定为下列业务内容，按规范 JSON 计算摘要：

* 源文件字节摘要 ``source_sha256``
* 方案/受试者/访视窗所依据的上下文摘要 ``context_sha256``
* 全部原始行台账摘要 ``source_rows_sha256``
* 每个受试者每次访视的采信结果、责任行、访视窗与阻断原因 ``visits``
* 偏离、复检问题、隔离行、行数守恒与锁库判定

生成时刻、耗时、来源别名、复核版本/状态和展示顺序都不进入封存边界。
因此同一业务内容重新生成或重新下载时凭证编号（seal）不变。
"""
import base64
import csv
import hashlib
import io
import json
import re
import unicodedata
import zipfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from app.config import RULE_VERSION

FORMAT = 'visitwindow-credential/1'
SEALED_KEYS = (
    'format',
    'rule_version',
    'source_sha256',
    'context_sha256',
    'source_rows_sha256',
    'visits',
    'deviations',
    'retest_issues',
    'quarantine',
    'counts',
    'balance',
)
SEAL_EXCLUDES = [
    '生成时刻与耗时',
    '来源别名 dataset 与批次 run_id 标签',
    '复核版本 revision 与复核状态 status',
    '页面或文件的展示顺序',
]
BUNDLE_FILES = ('manifest.json', 'evidence.json', 'checksums.json', 'source.csv', 'verify.py', 'SEAL.md')
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def canonical(value):
    """同一业务内容的唯一字节表示：键排序、紧凑分隔符、保留中文。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def pretty(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode('utf-8')


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _line(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _cells(value):
    return ['' if cell is None else str(cell) for cell in (value or [])]


def source_bytes(state):
    """返回导入时的原始字节；凭证内嵌 source.csv 以便独立复核。"""
    snapshot = state.get('input_snapshot') or {}
    encoded = snapshot.get('bytes_b64')
    if encoded:
        try:
            return base64.b64decode(encoded)
        except (ValueError, TypeError):
            return b''
    return b''


def parse_source(raw):
    """与记录采信同口径地按行号还原原始单元格，用于台账与责任行核对。"""
    if not raw:
        return None, {}
    text = None
    for encoding in ('utf-8-sig', 'gb18030'):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return None, {}
    reader = csv.reader(io.StringIO(text, newline=''), strict=True)
    try:
        header = list(next(reader))
    except StopIteration:
        return [], {}
    except csv.Error:
        return None, {}
    rows = {}
    try:
        for cells in reader:
            rows[reader.line_num] = list(cells)
    except csv.Error:
        pass
    return header, rows


def _canonical_context(context):
    """等效上下文归一：受试者/方案映射按键排序，个体生效窗与应访视按集合语义排序。"""
    normalized = dict(context or {})
    assignments = normalized.get('assignments')
    if isinstance(assignments, dict):
        normalized['assignments'] = {
            subject: sorted(entries, key=lambda entry: canonical(entry))
            for subject, entries in assignments.items()
        }
    for key in ('required_visits',):
        if isinstance(normalized.get(key), list):
            normalized[key] = sorted(normalized[key], key=str)
    return normalized


def _ledger_from_source(state, header, rows):
    """没有源台账的旧批次：按原始字节重建台账，原始行一条不丢。"""
    ledger = []
    quarantined = {_line(item.get('line')) for item in state.get('quarantine') or []}
    kept = {_line(record.get('_line')) for record in state.get('records') or []}
    for line in sorted(rows):
        cells = rows[line]
        if not any(cell.strip() for cell in cells):
            kind = 'blank'
        elif cells == header:
            kind = 'repeated_header'
        elif line in quarantined:
            kind = 'rejected'
        elif kept and line not in kept:
            kind = 'duplicate'
        else:
            kind = 'data'
        identity = '' if kind in ('blank', 'repeated_header') else (cells[0].strip() if cells else '')
        ledger.append({'line': line, 'kind': kind, 'id': identity, 'cells': _cells(cells)})
    return ledger


def source_ledger(state):
    """原始行台账。每条输入行都留痕：数据、空行、重复表头、隔离行。"""
    quarantined = {_line(item.get('line')) for item in state.get('quarantine') or []}
    rows = state.get('source_rows')
    if rows:
        ledger = []
        for row in rows:
            line = _line(row.get('line'))
            kind = row.get('kind', 'data')
            if line in quarantined and kind == 'data':
                kind = 'rejected'
            ledger.append({'line': line, 'kind': kind,
                           'id': row.get('id', ''), 'cells': _cells(row.get('cells'))})
        return sorted(ledger, key=lambda row: row['line'])
    header, parsed = parse_source(source_bytes(state))
    if header is not None:
        return _ledger_from_source(state, header, parsed)
    # 连源字节都没有时，至少保留采信行与隔离行，不丢记录。
    rebuilt = []
    for record in state.get('records') or []:
        rebuilt.append({'line': _line(record.get('_line')), 'kind': 'data',
                        'id': record.get('id', ''), 'cells': []})
    for item in state.get('quarantine') or []:
        rebuilt.append({'line': _line(item.get('line')), 'kind': 'rejected',
                        'id': item.get('id', ''), 'cells': _cells(item.get('cells'))})
    return sorted(rebuilt, key=lambda row: (row['line'], row['id']))


def source_header(state):
    header = state.get('source_header')
    if header:
        return {'line': _line(header.get('line'), 1), 'cells': _cells(header.get('cells'))}
    parsed, _ = parse_source(source_bytes(state))
    if parsed is not None:
        return {'line': 1, 'cells': _cells(parsed)}
    return None


def source_info(state, raw):
    return {
        'sha256': sha256_hex(raw) if raw else None,
        'bytes': len(raw),
        'encoding': state.get('encoding'),
    }


def _cells_by_line(ledger):
    return {row['line']: row['cells'] for row in ledger}


def _source_ref(role, record_id, line, cells):
    return {'role': role, 'id': record_id, 'line': line, 'cells': _cells(cells)}


def _result_summary(result, records, cells_map):
    selected_id = result.get('id')
    primary_id = result.get('primary_id') or selected_id
    selected = records.get(selected_id) or {}
    primary = records.get(primary_id) or {}
    selected_line = _line(result.get('line') or selected.get('_line'))
    primary_line = _line(result.get('primary_line') or primary.get('_line') or selected_line)
    summary = {
        'id': selected_id,
        'kind': selected.get('kind') or result.get('kind') or '',
        'primary_id': primary_id,
        'line': primary_line,
        'primary_line': primary_line,
        'selected_line': selected_line,
        'value_mg_dl': result.get('value_mg_dl'),
        'revision': result.get('revision'),
        'code': result.get('code'),
    }
    return summary, primary_line, selected_line, cells_map.get(primary_line, []), cells_map.get(selected_line, [])


def _ids_of(entry):
    return {part for part in (entry.get('id') or '').split(',') if part}


def _blocking_for(ids, deviation_codes, retest_issues):
    codes = set(deviation_codes)
    for entry in retest_issues:
        if (entry.get('id') in ids or entry.get('parent') in ids
                or _ids_of(entry) & ids):
            if entry.get('code'):
                codes.add(entry['code'])
    return sorted(codes)


def _primary_block(codes):
    """访视状态取最贴近采信结果的阻断原因：访视窗优先于复检问题。"""
    ordered = sorted(codes, key=lambda code: (not code.startswith('WINDOW_'), code))
    return ordered[0] if ordered else 'SETTLED'


def build_visits(state):
    context = state.get('context') or {}
    subjects = sorted((context.get('subjects') or {}).keys())
    visits_required = list(context.get('required_visits') or [])
    if not visits_required:
        plans = context.get('plans') or {}
        visits_required = sorted({visit for plan in plans.values() for visit in plan})
    records = {record.get('id'): record for record in (state.get('records') or [])}
    windows = {row.get('id'): row for row in (state.get('windows') or [])}
    deviations = list(state.get('deviations') or [])
    retest_issues = list(state.get('retest_issues') or [])
    cells_map = _cells_by_line(source_ledger(state))

    selected = {}
    for result in state.get('selected_results') or []:
        selected.setdefault((result.get('subject'), result.get('visit')), []).append(result)
    deviation_by_visit = {}
    for entry in deviations:
        if entry.get('subject') is not None and entry.get('visit') is not None:
            deviation_by_visit.setdefault((entry.get('subject'), entry.get('visit')), []).append(entry)

    visits = []
    for subject in subjects:
        for visit in visits_required:
            key = (subject, visit)
            candidates = sorted(selected.get(key, []), key=lambda result: str(result.get('id', '')))
            devs = deviation_by_visit.get(key, [])
            dev_codes = sorted({entry.get('code') for entry in devs if entry.get('code')})
            entry = {'subject': subject, 'visit': visit, 'status': 'SETTLED',
                     'result': None, 'candidates': [], 'protocol': None,
                     'window': None, 'day': None, 'in_window': False,
                     'sources': [], 'blocking': dev_codes}
            if not candidates:
                entry['status'] = 'MISSING_PRIMARY'
                entry['blocking'] = dev_codes or ['MISSING_PRIMARY']
            else:
                summaries = [_result_summary(candidate, records, cells_map) for candidate in candidates]
                entry['candidates'] = [summary[0] for summary in summaries]
                ambiguous = len(candidates) > 1 or 'DUPLICATE_PRIMARY' in dev_codes
                # 首次记录重复时不指定唯一采信结果，但两条原始行都要留痕。
                chosen_summaries = summaries if ambiguous else summaries[:1]
                if not ambiguous:
                    entry['result'] = summaries[0][0]
                    window = (windows.get(summaries[0][0]['primary_id'])
                              or windows.get(summaries[0][0]['id']))
                    if window:
                        entry['protocol'] = window.get('selected_protocol')
                        entry['window'] = {'start_day': window.get('start_day'),
                                           'end_day': window.get('end_day')}
                        entry['day'] = window.get('day')
                        entry['in_window'] = window.get('code') == 'IN_WINDOW'
                seen_lines = set()
                for summary, primary_line, selected_line, primary_cells, selected_cells in chosen_summaries:
                    for role, record_id, line, cells in (
                            ('primary', summary['primary_id'], primary_line, primary_cells),
                            ('selected', summary['id'], selected_line, selected_cells)):
                        if not line or line in seen_lines:
                            continue
                        seen_lines.add(line)
                        entry['sources'].append(_source_ref(role, record_id, line, cells))
                ids = {summary[0]['id'] for summary in summaries}
                ids.update(summary[0]['primary_id'] for summary in summaries)
                entry['blocking'] = _blocking_for(ids, dev_codes, retest_issues)
                if ambiguous:
                    entry['status'] = 'DUPLICATE_PRIMARY'
                    entry['blocking'] = sorted(set(entry['blocking']) | {'DUPLICATE_PRIMARY'})
                elif entry['blocking']:
                    # 采信结果或访视窗本身无偏离时，仍可能因复检问题阻断。
                    entry['status'] = _primary_block(entry['blocking'])
                else:
                    entry['status'] = 'SETTLED'
            entry['lines'] = sorted({_line(ref.get('line')) for ref in entry['sources'] if _line(ref.get('line'))})
            entry['digest'] = sha256_hex(canonical(entry))
            visits.append(entry)
    return sorted(visits, key=lambda visit: (str(visit['subject']), str(visit['visit'])))


def _sorted_deviations(state):
    return sorted((dict(item) for item in (state.get('deviations') or [])),
                  key=lambda item: (str(item.get('subject', '')), str(item.get('visit', '')),
                                    str(item.get('code', '')), str(item.get('id', '')),
                                    _line(item.get('line'))))


def _sorted_retest_issues(state):
    return sorted((dict(item) for item in (state.get('retest_issues') or [])),
                  key=lambda item: (str(item.get('id', '')), str(item.get('code', '')),
                                    str(item.get('parent', ''))))


def _sorted_quarantine(state):
    return sorted((dict(item) for item in (state.get('quarantine') or [])),
                  key=lambda item: (_line(item.get('line')), str(item.get('id', '')),
                                    str(item.get('code', ''))))


def build(state, with_files=True):
    """构造凭证文档。不读取生成时刻，因此同一业务内容逐字节可复现。"""
    ledger = source_ledger(state)
    raw = source_bytes(state)
    info = source_info(state, raw)
    context = state.get('context') or {}
    visits = build_visits(state)
    deviations = _sorted_deviations(state)
    retest_issues = _sorted_retest_issues(state)
    quarantine = _sorted_quarantine(state)
    counts = dict(state.get('counts') or {})
    balance = dict(state.get('balance') or {})
    rule_version = (state.get('manifest') or {}).get('rule_version') or RULE_VERSION

    evidence = {
        'format': FORMAT,
        'rule_version': rule_version,
        'source_sha256': info['sha256'],
        'context_sha256': sha256_hex(canonical(_canonical_context(context))),
        'source_rows_sha256': sha256_hex(canonical(ledger)),
        'visits': visits,
        'deviations': deviations,
        'retest_issues': retest_issues,
        'quarantine': quarantine,
        'counts': counts,
        'balance': balance,
        # 以下为复核所需的展开材料，不改变封存边界的计算口径：
        'source': info,
        'header': source_header(state),
        'source_rows': ledger,
        'context': context,
        'archive': {'status': (state.get('archive') or {}).get('status'),
                    'subjects': len(context.get('subjects') or {}),
                    'results': len(state.get('selected_results') or [])},
        'seal_boundary': {'includes': list(SEALED_KEYS), 'excludes': SEAL_EXCLUDES},
    }
    seal = seal_of(evidence)
    evidence['seal'] = seal

    manifest = {
        'format': FORMAT,
        'credential_id': seal,
        'seal': seal,
        'run_id': (state.get('manifest') or {}).get('run_id'),
        'sha256': (state.get('manifest') or {}).get('sha256'),
        'source_sha256': info['sha256'],
        'rule_version': rule_version,
        'timezone': (state.get('manifest') or {}).get('timezone', 'Asia/Shanghai'),
        'subjects': len(context.get('subjects') or {}),
        'visits': len(visits),
        'results': len(state.get('selected_results') or []),
        'seal_includes': list(SEALED_KEYS),
        'seal_excludes': SEAL_EXCLUDES,
        'verify': 'python verify.py',
    }

    files = {
        'manifest.json': pretty(manifest),
        'evidence.json': pretty(evidence),
        'source.csv': raw,
        'verify.py': VERIFY_SCRIPT.encode('utf-8'),
        'SEAL.md': SEAL_DOC.encode('utf-8'),
    }
    checksums = {
        'algorithm': 'sha256',
        'credential_id': seal,
        'seal': seal,
        'files': {name: sha256_hex(payload) for name, payload in sorted(files.items())},
    }
    files['checksums.json'] = pretty(checksums)
    document = {'manifest': manifest, 'evidence': evidence, 'checksums': checksums,
                'seal': seal, 'credential_id': seal}
    if with_files:
        document['files'] = files
        document['zip'] = pack(files)
    return document


def seal_of(evidence):
    payload = {key: evidence.get(key) for key in SEALED_KEYS}
    return sha256_hex(canonical(payload))


def pack(files):
    """固定条目顺序与 ZIP 元数据，保证同一业务内容逐字节可复现。"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name in BUNDLE_FILES:
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    return buffer.getvalue()


def build_bundle(state):
    return build(state)


def load_bundle(data):
    """读取凭证 ZIP，只访问已知条目，不解压到磁盘。"""
    if isinstance(data, dict):
        files = data.get('files')
        if isinstance(files, dict) and all(name in files for name in BUNDLE_FILES):
            payload = {name: files[name] for name in BUNDLE_FILES}
            parsed = {'files': payload}
            for name in ('manifest.json', 'evidence.json', 'checksums.json'):
                try:
                    parsed[name] = json.loads(payload[name].decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    return None, f'{name} 无法解析: {error}'
            return parsed, None
        return None, '凭证内容不完整'
    stream = io.BytesIO(bytes(data)) if isinstance(data, (bytes, bytearray)) else data
    if not hasattr(stream, 'seek'):
        return None, '不是有效的凭证包'
    try:
        archive = zipfile.ZipFile(stream)
        names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError) as error:
        return None, f'不是有效的凭证包: {error}'
    missing = [name for name in BUNDLE_FILES if name not in names]
    if missing:
        return None, f'缺少文件: {",".join(missing)}'
    files = {name: archive.read(name) for name in BUNDLE_FILES}
    parsed = {'files': files}
    for name in ('manifest.json', 'evidence.json', 'checksums.json'):
        try:
            parsed[name] = json.loads(files[name].decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            return None, f'{name} 无法解析: {error}'
    return parsed, None


def _visit_map(visits):
    return {(str(visit.get('subject')), str(visit.get('visit'))): visit for visit in visits or []}


COMPARE_FIELDS = ('result', 'window', 'protocol', 'day', 'in_window', 'status', 'blocking', 'sources')


def compare_visits(expected, actual):
    """按受试者访视比较两份凭证，指出变化的具体访视。"""
    left = _visit_map(expected)
    right = _visit_map(actual)
    changed, missing, extra = [], [], []
    for key in sorted(set(left) | set(right)):
        if key not in left:
            extra.append({'subject': key[0], 'visit': key[1]})
        elif key not in right:
            missing.append({'subject': key[0], 'visit': key[1]})
        else:
            fields = [field for field in COMPARE_FIELDS
                      if canonical(left[key].get(field)) != canonical(right[key].get(field))]
            if fields:
                changed.append({'subject': key[0], 'visit': key[1], 'fields': fields})
    return changed, missing, extra


def compare_evidence(expected, actual):
    """整体比较：给出变化的受试者访视，以及访视之外的封存区段。"""
    changed, missing, extra = compare_visits(expected.get('visits'), actual.get('visits'))
    sections = [key for key in SEALED_KEYS
                if key != 'visits' and canonical(expected.get(key)) != canonical(actual.get(key))]
    return {'changed': changed, 'missing': missing, 'extra': extra, 'sections': sections}


_FIELD_ALIASES = {'编号': 'id'}


def _source_row_dict(header_cells, cells):
    names = [_FIELD_ALIASES.get(str(name).strip(), str(name).strip()) for name in header_cells]
    return dict(zip(names, cells))


_SENTINELS = {'', '-', 'N/A', 'NULL', '未知'}


def _value_of(text, unit):
    """与记录采信同口径读取检验值：去千分位、可带单位后缀、空值视为无法复算。"""
    normalized = unicodedata.normalize('NFKC', str(text)).strip()
    if normalized.upper() in _SENTINELS or normalized in _SENTINELS:
        return None
    if unit and normalized.endswith(unit):
        normalized = normalized[:-len(unit)].strip()
    if ',' in normalized:
        if not re.fullmatch(r'[+-]?\d{1,3}(,\d{3})+(\.\d+)?', normalized):
            return None
        normalized = normalized.replace(',', '')
    try:
        return Decimal(normalized)
    except InvalidOperation:
        return None


def _audit_visits(evidence, rows, report):
    """仅用包内材料复算：责任行、方案版本、访视窗、访视日与检验值必须自洽。"""
    header = evidence.get('header') or {}
    context = evidence.get('context') or {}
    visits = evidence.get('visits') or []
    header_cells = _cells(header.get('cells'))
    if not header_cells or not context:
        return
    subjects = context.get('subjects') or {}
    assignments = context.get('assignments') or {}
    plans = context.get('plans') or {}
    units = context.get('units') or {}
    required = list(context.get('required_visits') or [])
    zone = timezone(timedelta(hours=8))

    def label(visit):
        return f"{visit.get('subject')} {visit.get('visit')}"

    if len(visits) != len(subjects) * len(required):
        report['errors'].append(
            f"访视数量不符: 应有 {len(subjects) * len(required)} 次，实际 {len(visits)} 次")
    seen = {(str(v.get('subject')), str(v.get('visit'))) for v in visits}
    for subject in subjects:
        for visit in required:
            if (str(subject), str(visit)) not in seen:
                report['errors'].append(f'访视缺失: {subject} {visit}')

    for visit in visits:
        tag = label(visit)
        result = visit.get('result')
        refs = visit.get('sources') or []
        if visit.get('status') == 'MISSING_PRIMARY':
            if result is not None or refs:
                report['errors'].append(f'漏访不应有采信结果或责任行: {tag}')
            if 'MISSING_PRIMARY' not in (visit.get('blocking') or []):
                report['errors'].append(f'漏访缺少阻断原因: {tag}')
            continue
        if visit.get('status') == 'DUPLICATE_PRIMARY':
            if not ('DUPLICATE_PRIMARY' in (visit.get('blocking') or [])):
                report['errors'].append(f'重复首次缺少阻断原因: {tag}')
            if len(refs) < 2:
                report['errors'].append(f'重复首次必须保留每条原始行: {tag}')
            for ref in refs:
                cells = rows.get(_line(ref.get('line')))
                if cells is None:
                    report['errors'].append(f"责任行缺失: {tag} 第{_line(ref.get('line'))}行")
                    continue
                parsed = _source_row_dict(header_cells, cells)
                if parsed.get('subject') != str(visit.get('subject')) or parsed.get('visit') != str(visit.get('visit')):
                    report['errors'].append(f"责任行不属于该受试者访视: {tag} 第{_line(ref.get('line'))}行")
                if _cells(cells) != _cells(ref.get('cells')):
                    report['errors'].append(f"责任行内容不符: {tag} 第{_line(ref.get('line'))}行")
            continue
        if not result or not refs:
            report['errors'].append(f'缺少采信结果或责任行: {tag}')
            continue
        primary_ref = next((ref for ref in refs if ref.get('role') == 'primary'), refs[0])
        selected_ref = next((ref for ref in refs if ref.get('role') == 'selected'), None)
        primary_line = _line(primary_ref.get('line'))
        primary_cells = rows.get(primary_line)
        if primary_cells is None:
            report['errors'].append(f'责任行缺失: {tag} 第{primary_line}行')
            continue
        primary = _source_row_dict(header_cells, primary_cells)
        if primary.get('id') != result.get('primary_id'):
            report['errors'].append(f"首次记录行号不符: {tag} 第{primary_line}行")
        if primary.get('subject') != str(visit.get('subject')) or primary.get('visit') != str(visit.get('visit')):
            report['errors'].append(f'责任行不属于该受试者访视: {tag} 第{primary_line}行')
        if _cells(primary_cells) != _cells(primary_ref.get('cells')):
            report['errors'].append(f'责任行内容不符: {tag} 第{primary_line}行')

        if result.get('kind') == 'RETEST':
            if result.get('id') == result.get('primary_id'):
                report['errors'].append(f'采信复检缺少复检行: {tag}')
            if not selected_ref:
                report['errors'].append(f'采信复检缺少复检责任行: {tag}')
            else:
                selected_line = _line(selected_ref.get('line'))
                selected_cells = rows.get(selected_line)
                if selected_cells is None:
                    report['errors'].append(f'复检责任行缺失: {tag} 第{selected_line}行')
                else:
                    selected = _source_row_dict(header_cells, selected_cells)
                    if selected.get('id') != result.get('id'):
                        report['errors'].append(f"复检记录行号不符: {tag} 第{selected_line}行")
                    if selected.get('kind') != 'RETEST' or selected.get('parent') != result.get('primary_id'):
                        report['errors'].append(f'复检责任行未引用该首次记录: {tag} 第{selected_line}行')
                    if _cells(selected_cells) != _cells(selected_ref.get('cells')):
                        report['errors'].append(f'复检责任行内容不符: {tag} 第{selected_line}行')
        elif result.get('kind') != 'PRIMARY':
            report['errors'].append(f'采信结果类型无效: {tag}')
        if result.get('id') == result.get('primary_id') and selected_ref:
            report['errors'].append(f'首次记录采信却带复检责任行: {tag}')

        # 方案版本：按发生时刻与个体生效窗唯一匹配，不能用全局最新版。
        try:
            at = datetime.fromisoformat(str(primary.get('at')).replace('Z', '+00:00'))
            if at.tzinfo is None:
                raise ValueError('no offset')
            at = at.astimezone(timezone.utc)
        except (TypeError, ValueError):
            report['errors'].append(f'责任行采样时刻无效: {tag}')
            continue
        matches = []
        for assignment in assignments.get(str(visit.get('subject')), []):
            try:
                start = datetime.fromisoformat(str(assignment.get('start')).replace('Z', '+00:00'))
                end = datetime.fromisoformat(str(assignment.get('end')).replace('Z', '+00:00'))
            except (TypeError, ValueError):
                continue
            if start.tzinfo is None or end.tzinfo is None:
                continue
            if start.astimezone(timezone.utc) <= at < end.astimezone(timezone.utc):
                matches.append(assignment.get('version'))
        if len(matches) != 1:
            report['errors'].append(f'方案生效窗不唯一: {tag}')
            continue
        if matches[0] != visit.get('protocol'):
            report['errors'].append(f"方案版本不符: {tag} 应为 {matches[0]}")
            continue
        try:
            enrolled = datetime.fromisoformat(str(primary.get('enrolled')).replace('Z', '+00:00'))
            if enrolled.tzinfo is None:
                raise ValueError('no offset')
            enrolled = enrolled.astimezone(timezone.utc)
        except (TypeError, ValueError):
            report['errors'].append(f'责任行入组基准无效: {tag}')
            continue
        declared = subjects.get(str(visit.get('subject')))
        try:
            declared_at = datetime.fromisoformat(str(declared).replace('Z', '+00:00'))
            if declared_at.tzinfo is not None and enrolled != declared_at.astimezone(timezone.utc):
                report['errors'].append(f'入组基准与上下文不符: {tag}')
        except (TypeError, ValueError):
            report['errors'].append(f'上下文入组基准无效: {tag}')
        day = (at.astimezone(zone).date() - enrolled.astimezone(zone).date()).days
        if visit.get('day') != day:
            report['errors'].append(f'访视日不符: {tag} 应为第{day}天')
        window = (plans.get(matches[0]) or {}).get(str(visit.get('visit')))
        if not window or len(window) != 2:
            report['errors'].append(f'访视窗缺失: {tag}')
            continue
        start, end = int(window[0]), int(window[1])
        if visit.get('window') != {'start_day': start, 'end_day': end}:
            report['errors'].append(f'访视窗不符: {tag} 应为[{start},{end})')
        in_window = start <= day < end
        if visit.get('in_window') != in_window:
            report['errors'].append(f'窗内判定不符: {tag}')
        if in_window and str(visit.get('status', '')).startswith('WINDOW_'):
            report['errors'].append(f'窗内访视被标为偏离: {tag}')
        if not in_window and visit.get('status') == 'SETTLED':
            report['errors'].append(f'窗外访视未标偏离: {tag}')
        if visit.get('status') == 'SETTLED' and (visit.get('blocking') or []):
            report['errors'].append(f'阻断项与采信状态矛盾: {tag}')

        # 采信检验值必须能由责任行的原值与单位换算得到。
        value_row = primary
        if result.get('kind') == 'RETEST' and selected_ref:
            selected_cells = rows.get(_line(selected_ref.get('line')))
            if selected_cells is not None:
                value_row = _source_row_dict(header_cells, selected_cells)
        factor = units.get(value_row.get('unit'))
        value = _value_of(value_row.get('value'), value_row.get('unit'))
        if factor is not None and value is not None:
            expected_value = value * Decimal(str(factor))
            if Decimal(str(result.get('value_mg_dl'))) != expected_value:
                report['errors'].append(f'检验值与责任行不符: {tag}')
        elif factor is not None:
            report['errors'].append(f'检验值无法由责任行复算: {tag}')


def _integrity(parsed, report):
    manifest = parsed['manifest.json']
    evidence = parsed['evidence.json']
    checksums = parsed['checksums.json']
    files = parsed['files']

    for name in ('manifest.json', 'evidence.json', 'source.csv', 'verify.py', 'SEAL.md'):
        expected_hash = (checksums.get('files') or {}).get(name)
        if expected_hash is None:
            report['errors'].append(f'校验清单缺少 {name}')
        elif sha256_hex(files[name]) != expected_hash:
            report['errors'].append(f'{name} 摘要不符')

    computed = seal_of(evidence)
    report['seal'] = computed
    report['credential_id'] = computed
    if evidence.get('seal') != computed:
        report['errors'].append('evidence 自带 seal 与封存内容不符')
    if manifest.get('seal') != computed:
        report['errors'].append('manifest seal 与 evidence 不符')
    if checksums.get('seal') != computed:
        report['errors'].append('checksums seal 不符')

    for visit in evidence.get('visits') or []:
        body = {key: value for key, value in visit.items() if key != 'digest'}
        if sha256_hex(canonical(body)) != visit.get('digest'):
            report['errors'].append(f"访视摘要不符: {visit.get('subject')} {visit.get('visit')}")
    if sha256_hex(canonical(evidence.get('source_rows') or [])) != evidence.get('source_rows_sha256'):
        report['errors'].append('原始行台账摘要不符')

    raw = files['source.csv']
    source_hash = sha256_hex(raw) if raw else None
    if evidence.get('source_sha256') not in (None, source_hash):
        report['errors'].append('source.csv 与源摘要不符')
    if manifest.get('source_sha256') not in (None, source_hash):
        report['errors'].append('source.csv 与 manifest 源摘要不符')

    header, rows = parse_source(raw)
    if raw:
        if header is None:
            report['errors'].append('source.csv 编码无法识别')
        else:
            stored = evidence.get('header') or {}
            if stored and _cells(stored.get('cells')) != _cells(header):
                report['errors'].append('表头与 source.csv 不符')
            ledger_lines = set()
            for row in evidence.get('source_rows') or []:
                line = _line(row.get('line'))
                ledger_lines.add(line)
                if line not in rows:
                    report['errors'].append(f'原始行缺失: 第{line}行')
                elif _cells(rows[line]) != _cells(row.get('cells')):
                    report['errors'].append(f'原始行内容不符: 第{line}行')
            header_line = 1
            stored = evidence.get('header') or {}
            if stored:
                header_line = _line(stored.get('line'), 1)
            for line in rows:
                if line > header_line and line not in ledger_lines:
                    report['errors'].append(f'原始行台账丢失记录: 第{line}行')
            for visit in evidence.get('visits') or []:
                for ref in visit.get('sources') or []:
                    line = _line(ref.get('line'))
                    if line and line not in rows:
                        report['errors'].append(
                            f"责任行缺失: {visit.get('subject')} {visit.get('visit')} 第{line}行")
                    elif line and _cells(rows[line]) != _cells(ref.get('cells')):
                        report['errors'].append(
                            f"责任行内容不符: {visit.get('subject')} {visit.get('visit')} 第{line}行")
    _audit_visits(evidence, rows, report)


def verify_bundle(data, expected=None):
    """离线/在线校验。expected 为当前批次状态或已构造的 evidence。"""
    report = {'ok': False, 'errors': [], 'changed': [], 'missing': [], 'extra': [],
              'sections': [], 'seal': None, 'credential_id': None, 'blocked': False}
    if isinstance(data, dict) and 'files' in data:
        parsed = data
    else:
        parsed, error = load_bundle(data)
        if error:
            report['errors'].append(error)
            report['blocked'] = True
            return report
    _integrity(parsed, report)

    if expected is not None:
        expected_evidence = (expected if isinstance(expected, dict) and 'seal' in expected
                             and 'source_rows' in expected else build(expected)['evidence'])
        diff = compare_evidence(expected_evidence, parsed['evidence.json'])
        report['changed'] = diff['changed']
        report['missing'] = diff['missing']
        report['extra'] = diff['extra']
        report['sections'] = diff['sections']
        if diff['changed'] or diff['missing'] or diff['extra']:
            report['errors'].append('凭证与当前批次的采信结果或访视窗不一致')
        elif diff['sections']:
            report['errors'].append('凭证与当前批次的封存区段不一致: ' + ','.join(diff['sections']))

    report['blocked'] = bool(report['errors'])
    report['ok'] = not report['errors']
    return report


def changed_visits_text(diff):
    parts = []
    for item in diff.get('changed') or []:
        parts.append(f"{item['subject']} {item['visit']}（{','.join(item['fields'])}）")
    for item in diff.get('missing') or []:
        parts.append(f"{item['subject']} {item['visit']}（旧版有、当前无）")
    for item in diff.get('extra') or []:
        parts.append(f"{item['subject']} {item['visit']}（当前有、旧版无）")
    return '；'.join(parts)


SEAL_DOC = """# 冻结凭证校验依据

本包是同一批次业务内容的封存凭证。凭证编号（seal）只由以下内容决定：

1. `source.csv` 的 SHA-256（导入原字节）
2. 方案与访视窗上下文的规范 JSON 摘要
3. 全部原始行台账摘要
4. 每个受试者每次访视的采信结果、责任行、访视窗与阻断原因
5. 偏离、复检问题、隔离行、行数守恒与锁库判定

生成时刻、耗时、来源别名、复核版本与复核状态、展示顺序都不在封存边界内。
重新生成或重新下载同一业务内容时 seal 不变，不会因时间或顺序变化而失效。

## 包内文件

| 文件 | 用途 |
|---|---|
| `manifest.json` | 凭证编号、批次与规则版本、封存边界说明 |
| `evidence.json` | 每次访视的采信结果、责任行、访视窗、阻断项与原始行台账 |
| `source.csv` | 导入时的原始字节，原始行逐行可核 |
| `checksums.json` | 包内各文件 SHA-256 与凭证 seal |
| `verify.py` | 只依赖标准库的独立复核脚本 |
| `SEAL.md` | 本说明 |

## 复核

```sh
python verify.py                 # 自检本包（摘要、seal、原始行、责任行）
python verify.py other.zip       # 与另一份凭证比对，列出变化的受试者访视
```

校验失败或与当前批次不一致时退出码为 1，并指出具体“受试者 + 访视”
及变化字段（`result` 表示采信结果，`window` 表示访视窗），复核应阻断。
"""


VERIFY_SCRIPT = r'''#!/usr/bin/env python3
"""独立复核脚本：只依赖 Python 标准库，不导入本项目代码。"""
import csv
import hashlib
import io
import json
import os
import re
import sys
import unicodedata
import zipfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

SEALED_KEYS = ('format', 'rule_version', 'source_sha256', 'context_sha256',
               'source_rows_sha256', 'visits', 'deviations', 'retest_issues',
               'quarantine', 'counts', 'balance')
FILES = ('manifest.json', 'evidence.json', 'checksums.json', 'source.csv', 'verify.py', 'SEAL.md')
FIELDS = ('result', 'window', 'protocol', 'day', 'in_window', 'status', 'blocking', 'sources')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def load(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            missing = [name for name in FILES if name not in names]
            if missing:
                raise ValueError('缺少文件: ' + ','.join(missing))
            files = {name: archive.read(name) for name in FILES}
    else:
        files = {name: open(os.path.join(path, name), 'rb').read() for name in FILES}
    return (json.loads(files['manifest.json'].decode('utf-8')),
            json.loads(files['evidence.json'].decode('utf-8')),
            json.loads(files['checksums.json'].decode('utf-8')),
            files)


def cells(value):
    return ['' if cell is None else str(cell) for cell in (value or [])]


def parse_source(raw):
    text = None
    for encoding in ('utf-8-sig', 'gb18030'):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return None, {}
    reader = csv.reader(io.StringIO(text, newline=''), strict=True)
    try:
        header = list(next(reader))
    except StopIteration:
        return [], {}
    except csv.Error:
        return None, {}
    rows = {}
    try:
        for row in reader:
            rows[reader.line_num] = list(row)
    except csv.Error:
        pass
    return header, rows


def row_dict(header_cells, row_cells):
    names = ['id' if str(name).strip() == '编号' else str(name).strip() for name in header_cells]
    return dict(zip(names, row_cells))


SENTINELS = ('', '-', 'N/A', 'NULL', '未知')


def value_of(text, unit):
    normalized = unicodedata.normalize('NFKC', str(text)).strip()
    if normalized.upper() in SENTINELS or normalized in SENTINELS:
        return None
    if unit and normalized.endswith(unit):
        normalized = normalized[:-len(unit)].strip()
    if ',' in normalized:
        if not re.fullmatch(r'[+-]?\d{1,3}(,\d{3})+(\.\d+)?', normalized):
            return None
        normalized = normalized.replace(',', '')
    try:
        return Decimal(normalized)
    except InvalidOperation:
        return None


def moment(value):
    at = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if at.tzinfo is None:
        raise ValueError('缺少时区偏移')
    return at.astimezone(timezone.utc)


def audit(evidence, rows, errors):
    """只用包内 source.csv 与 context 复算责任行、方案版本、访视窗与检验值。"""
    header_cells = cells((evidence.get('header') or {}).get('cells'))
    context = evidence.get('context') or {}
    visits = evidence.get('visits') or []
    if not header_cells or not context:
        return
    subjects = context.get('subjects') or {}
    required = list(context.get('required_visits') or [])
    plans = context.get('plans') or {}
    units = context.get('units') or {}
    zone = timezone(timedelta(hours=8))
    if len(visits) != len(subjects) * len(required):
        errors.append('访视数量不符: 应有 %d 次，实际 %d 次' % (len(subjects) * len(required), len(visits)))
    seen = {(str(v.get('subject')), str(v.get('visit'))) for v in visits}
    for subject in subjects:
        for visit in required:
            if (str(subject), str(visit)) not in seen:
                errors.append('访视缺失: %s %s' % (subject, visit))
    for visit in visits:
        tag = '%s %s' % (visit.get('subject'), visit.get('visit'))
        result = visit.get('result')
        refs = visit.get('sources') or []
        if visit.get('status') == 'MISSING_PRIMARY':
            if result is not None or refs:
                errors.append('漏访不应有采信结果或责任行: ' + tag)
            if 'MISSING_PRIMARY' not in (visit.get('blocking') or []):
                errors.append('漏访缺少阻断原因: ' + tag)
            continue
        if visit.get('status') == 'DUPLICATE_PRIMARY':
            if 'DUPLICATE_PRIMARY' not in (visit.get('blocking') or []):
                errors.append('重复首次缺少阻断原因: ' + tag)
            if len(refs) < 2:
                errors.append('重复首次必须保留每条原始行: ' + tag)
            for ref in refs:
                found = rows.get(int(ref.get('line') or 0))
                if found is None:
                    errors.append('责任行缺失: %s 第%s行' % (tag, ref.get('line')))
                    continue
                parsed = row_dict(header_cells, found)
                if parsed.get('subject') != str(visit.get('subject')) or parsed.get('visit') != str(visit.get('visit')):
                    errors.append('责任行不属于该受试者访视: %s 第%s行' % (tag, ref.get('line')))
                if cells(found) != cells(ref.get('cells')):
                    errors.append('责任行内容不符: %s 第%s行' % (tag, ref.get('line')))
            continue
        if not result or not refs:
            errors.append('缺少采信结果或责任行: ' + tag)
            continue
        primary_ref = next((ref for ref in refs if ref.get('role') == 'primary'), refs[0])
        selected_ref = next((ref for ref in refs if ref.get('role') == 'selected'), None)
        primary_row = rows.get(int(primary_ref.get('line') or 0))
        if primary_row is None:
            errors.append('责任行缺失: %s 第%s行' % (tag, primary_ref.get('line')))
            continue
        primary = row_dict(header_cells, primary_row)
        if primary.get('id') != result.get('primary_id'):
            errors.append('首次记录行号不符: ' + tag)
        if primary.get('subject') != str(visit.get('subject')) or primary.get('visit') != str(visit.get('visit')):
            errors.append('责任行不属于该受试者访视: ' + tag)
        if cells(primary_row) != cells(primary_ref.get('cells')):
            errors.append('责任行内容不符: %s 第%s行' % (tag, primary_ref.get('line')))
        value_row = primary
        if result.get('kind') == 'RETEST':
            if result.get('id') == result.get('primary_id') or not selected_ref:
                errors.append('采信复检缺少复检责任行: ' + tag)
            else:
                selected_row = rows.get(int(selected_ref.get('line') or 0))
                if selected_row is None:
                    errors.append('复检责任行缺失: %s 第%s行' % (tag, selected_ref.get('line')))
                else:
                    selected = row_dict(header_cells, selected_row)
                    if selected.get('id') != result.get('id'):
                        errors.append('复检记录行号不符: ' + tag)
                    if selected.get('kind') != 'RETEST' or selected.get('parent') != result.get('primary_id'):
                        errors.append('复检责任行未引用该首次记录: ' + tag)
                    if cells(selected_row) != cells(selected_ref.get('cells')):
                        errors.append('复检责任行内容不符: %s 第%s行' % (tag, selected_ref.get('line')))
                    value_row = selected
        elif result.get('kind') != 'PRIMARY':
            errors.append('采信结果类型无效: ' + tag)
        if result.get('id') == result.get('primary_id') and selected_ref:
            errors.append('首次记录采信却带复检责任行: ' + tag)
        try:
            at = moment(primary.get('at'))
        except (TypeError, ValueError):
            errors.append('责任行采样时刻无效: ' + tag)
            continue
        matches = []
        for assignment in (context.get('assignments') or {}).get(str(visit.get('subject')), []):
            try:
                start, end = moment(assignment.get('start')), moment(assignment.get('end'))
            except (TypeError, ValueError):
                continue
            if start <= at < end:
                matches.append(assignment.get('version'))
        if len(matches) != 1:
            errors.append('方案生效窗不唯一: ' + tag)
            continue
        if matches[0] != visit.get('protocol'):
            errors.append('方案版本不符: %s 应为 %s' % (tag, matches[0]))
            continue
        try:
            enrolled = moment(primary.get('enrolled'))
            declared = subjects.get(str(visit.get('subject')))
            if declared and moment(declared) != enrolled:
                errors.append('入组基准与上下文不符: ' + tag)
        except (TypeError, ValueError):
            errors.append('责任行入组基准无效: ' + tag)
            continue
        day = (at.astimezone(zone).date() - enrolled.astimezone(zone).date()).days
        if visit.get('day') != day:
            errors.append('访视日不符: %s 应为第%d天' % (tag, day))
        window = (plans.get(matches[0]) or {}).get(str(visit.get('visit')))
        if not window or len(window) != 2:
            errors.append('访视窗缺失: ' + tag)
            continue
        start, end = int(window[0]), int(window[1])
        if visit.get('window') != {'start_day': start, 'end_day': end}:
            errors.append('访视窗不符: %s 应为[%d,%d)' % (tag, start, end))
        in_window = start <= day < end
        if visit.get('in_window') != in_window:
            errors.append('窗内判定不符: ' + tag)
        if in_window and str(visit.get('status', '')).startswith('WINDOW_'):
            errors.append('窗内访视被标为偏离: ' + tag)
        if not in_window and visit.get('status') == 'SETTLED':
            errors.append('窗外访视未标偏离: ' + tag)
        factor = units.get(value_row.get('unit'))
        value = value_of(value_row.get('value'), value_row.get('unit'))
        if factor is not None and value is not None:
            if Decimal(str(result.get('value_mg_dl'))) != value * Decimal(str(factor)):
                errors.append('检验值与责任行不符: ' + tag)
        elif factor is not None:
            errors.append('检验值无法由责任行复算: ' + tag)


def check(path):
    errors = []
    try:
        manifest, evidence, checksums, files = load(path)
    except Exception as error:
        return {'ok': False, 'errors': ['不是有效的凭证包: %s' % error], 'changed': []}
    for name in ('manifest.json', 'evidence.json', 'source.csv', 'verify.py', 'SEAL.md'):
        if (checksums.get('files') or {}).get(name) != digest(files[name]):
            errors.append(name + ' 摘要不符')
    seal = digest({key: evidence.get(key) for key in SEALED_KEYS})
    if evidence.get('seal') != seal or manifest.get('seal') != seal or checksums.get('seal') != seal:
        errors.append('seal 与封存内容不符')
    for visit in evidence.get('visits') or []:
        body = {key: value for key, value in visit.items() if key != 'digest'}
        if visit.get('digest') != digest(body):
            errors.append('访视摘要不符: %s %s' % (visit.get('subject'), visit.get('visit')))
    if evidence.get('source_rows_sha256') != digest(evidence.get('source_rows') or []):
        errors.append('原始行台账摘要不符')
    raw = files['source.csv']
    if raw and evidence.get('source_sha256') != digest(raw):
        errors.append('source.csv 与源摘要不符')
    if raw:
        header, rows = parse_source(raw)
        if header is None:
            errors.append('source.csv 编码无法识别')
        else:
            stored = evidence.get('header') or {}
            if stored and cells(stored.get('cells')) != cells(header):
                errors.append('表头不符')
            ledger_lines = set()
            for row in evidence.get('source_rows') or []:
                line = int(row.get('line') or 0)
                ledger_lines.add(line)
                if line not in rows:
                    errors.append('原始行缺失: 第%d行' % line)
                elif cells(rows[line]) != cells(row.get('cells')):
                    errors.append('原始行内容不符: 第%d行' % line)
            header_line = int((stored or {}).get('line') or 1)
            for line in rows:
                if line > header_line and line not in ledger_lines:
                    errors.append('原始行台账丢失记录: 第%d行' % line)
            for visit in evidence.get('visits') or []:
                for ref in visit.get('sources') or []:
                    line = int(ref.get('line') or 0)
                    if line and line not in rows:
                        errors.append('责任行缺失: %s %s 第%d行' % (visit.get('subject'), visit.get('visit'), line))
                    elif line and cells(rows[line]) != cells(ref.get('cells')):
                        errors.append('责任行内容不符: %s %s 第%d行' % (visit.get('subject'), visit.get('visit'), line))
            audit(evidence, rows, errors)
    return {'ok': not errors, 'errors': errors, 'seal': seal, 'evidence': evidence, 'changed': []}


def compare(left, right):
    a = {(str(v.get('subject')), str(v.get('visit'))): v for v in left.get('visits') or []}
    b = {(str(v.get('subject')), str(v.get('visit'))): v for v in right.get('visits') or []}
    changed, missing, extra = [], [], []
    for key in sorted(set(a) | set(b)):
        if key not in a:
            extra.append({'subject': key[0], 'visit': key[1]})
        elif key not in b:
            missing.append({'subject': key[0], 'visit': key[1]})
        else:
            diff = [field for field in FIELDS if canonical(a[key].get(field)) != canonical(b[key].get(field))]
            if diff:
                changed.append({'subject': key[0], 'visit': key[1], 'fields': diff})
    return changed, missing, extra


def main():
    args = sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    target = args[0] if args else here
    report = check(target)
    output = {'ok': report.get('ok'), 'seal': report.get('seal'),
              'errors': report.get('errors') or [], 'changed': [], 'missing': [], 'extra': []}
    if len(args) > 1:
        other = check(args[1])
        if not report.get('ok') or not other.get('ok'):
            output['ok'] = False
            output['errors'] += other.get('errors') or []
        else:
            changed, missing, extra = compare(report['evidence'], other['evidence'])
            output['changed'], output['missing'], output['extra'] = changed, missing, extra
            if changed or missing or extra:
                output['ok'] = False
                output['errors'].append('两份凭证的采信结果或访视窗不一致')
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
'''


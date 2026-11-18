import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone
from app.errors import BusinessError

def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con=sqlite3.connect(path,timeout=15)
    con.row_factory=sqlite3.Row
    con.execute('PRAGMA journal_mode=WAL')
    con.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL, result TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT '待复核')")
    # 凭证版本保留历史：替换失败或新凭证不合法时，旧版仍是当前凭证。
    con.execute("CREATE TABLE IF NOT EXISTS credentials (run_id TEXT NOT NULL, seal TEXT NOT NULL, package BLOB NOT NULL, created_at TEXT NOT NULL, current INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(run_id, seal))")
    return con

def save(path, result):
    run_id=result['manifest']['run_id']
    with connect(path) as con:
        con.execute('INSERT OR IGNORE INTO runs(id,digest,result) VALUES(?,?,?)', (run_id,result['manifest']['sha256'],json.dumps(result,ensure_ascii=False)))
    return get(path,run_id)

def get(path, run_id):
    with connect(path) as con: row=con.execute('SELECT * FROM runs WHERE id=?',(run_id,)).fetchone()
    if not row: raise BusinessError('NOT_FOUND','批次不存在',404)
    result=json.loads(row['result']);result.update(revision=row['revision'],status=row['status'])
    return result

def history(path):
    with connect(path) as con:
        return [dict(r) for r in con.execute('SELECT id,revision,status FROM runs ORDER BY rowid DESC LIMIT 100')]

def review(path,run_id,revision):
    with connect(path) as con:
        cur=con.execute('UPDATE runs SET revision=revision+1,status=? WHERE id=? AND revision=?',('已复核',run_id,revision))
        if cur.rowcount!=1:
            if not con.execute('SELECT 1 FROM runs WHERE id=?',(run_id,)).fetchone():
                raise BusinessError('NOT_FOUND','批次不存在',404)
            raise BusinessError('STALE_VERSION','复核版本已更新，请刷新',409)
    return get(path,run_id)

def _credential_row(row):
    return {'run_id':row['run_id'],'seal':row['seal'],'package':row['package'],
            'created_at':row['created_at'],'current':bool(row['current'])}

def current_credential(path,run_id):
    """当前生效的凭证；没有下载过则为 None。"""
    with connect(path) as con:
        row=con.execute('SELECT * FROM credentials WHERE run_id=? AND current=1 ORDER BY created_at DESC LIMIT 1',(run_id,)).fetchone()
    return _credential_row(row) if row else None

def credential(path,run_id,seal):
    with connect(path) as con:
        row=con.execute('SELECT * FROM credentials WHERE run_id=? AND seal=?',(run_id,seal)).fetchone()
    if not row: raise BusinessError('CREDENTIAL_NOT_FOUND','凭证不存在',404)
    return _credential_row(row)

def credentials(path,run_id):
    with connect(path) as con:
        return [{'seal':row['seal'],'created_at':row['created_at'],'current':bool(row['current'])}
                for row in con.execute('SELECT seal,created_at,current FROM credentials WHERE run_id=? ORDER BY created_at,seal',(run_id,))]

def save_credential(path,run_id,document):
    """保存并切换当前凭证。整事务执行；失败时旧版凭证仍是当前版本。"""
    created=datetime.now(timezone.utc).isoformat()
    with connect(path) as con:
        con.execute('INSERT OR IGNORE INTO credentials(run_id,seal,package,created_at,current) VALUES(?,?,?,?,0)',
                    (run_id,document['seal'],document['zip'],created))
        con.execute('UPDATE credentials SET current=0 WHERE run_id=?',(run_id,))
        cur=con.execute('UPDATE credentials SET current=1 WHERE run_id=? AND seal=?',(run_id,document['seal']))
        if cur.rowcount!=1: raise BusinessError('CREDENTIAL_SAVE_FAILED','凭证保存失败',500)
    return current_credential(path,run_id)

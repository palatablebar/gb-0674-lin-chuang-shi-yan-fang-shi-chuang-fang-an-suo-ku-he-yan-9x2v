from contextlib import asynccontextmanager
from importlib import import_module
from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from app.config import ROOT, META, MODULES, DB_PATH
from app.errors import BusinessError
from app.engine import evaluate
from app import store
from app import credential
from app.credential import changed_visits_text

@asynccontextmanager
async def lifespan(app):
    store.save(DB_PATH,evaluate())
    yield
app=FastAPI(title=META['title'],lifespan=lifespan)
app.mount('/static',StaticFiles(directory=str(ROOT/'app/static')),name='static')
@app.exception_handler(BusinessError)
async def business_error(request:Request,error:BusinessError):
    return JSONResponse({'code':error.code,'detail':error.message,**error.extra},status_code=error.status)
@app.get('/')
def home():
    return RedirectResponse('/'+MODULES[0],status_code=303)
@app.get('/healthz')
def health():
    return {'status':'ok','project':META['short']}
@app.post('/api/runs')
def create(payload:dict=Body(default={})):
    return store.save(DB_PATH,evaluate(payload))
@app.post('/api/runs/{run_id}/rerun')
def rerun(run_id:str):
    previous=store.get(DB_PATH,run_id)
    if 'input_snapshot' not in previous:
        raise BusinessError('INPUT_SNAPSHOT_MISSING','旧批缺少源快照，请重新导入')
    return store.save(DB_PATH,evaluate({'dataset':previous['source']},snapshot=previous['input_snapshot']))
@app.get('/api/runs')
def runs():
    return store.history(DB_PATH)
@app.get('/api/runs/{run_id}')
def run(run_id:str):
    return store.get(DB_PATH,run_id)
@app.post('/api/runs/{run_id}/review')
def review(run_id:str,payload:dict=Body(...)):
    revision=payload.get('revision')
    if not isinstance(revision,int) or revision<1: raise BusinessError('BAD_REVISION','版本号须为正整数')
    return store.review(DB_PATH,run_id,revision)

def _zip_response(package,run_id,seal):
    return Response(package,media_type='application/zip',headers={
        'Content-Disposition':f'attachment; filename="{run_id}-{seal[:12]}.zip"',
        'X-Credential-Seal':seal})

@app.get('/api/export/{run_id}')
def export(run_id:str):
    """下载即封存。业务内容变化时阻断并指出受试者访视，旧版凭证保持可用。"""
    result=store.get(DB_PATH,run_id)
    candidate=credential.build(result)
    self_check=credential.verify_bundle(candidate['zip'])
    current=store.current_credential(DB_PATH,run_id)
    diff=None; current_error=None
    if current is not None:
        parsed,current_error=credential.load_bundle(current['package'])
        if parsed is not None:
            diff=credential.compare_evidence(parsed['evidence.json'],candidate['evidence'])
    changed=diff and (diff['changed'] or diff['missing'] or diff['extra'] or diff['sections'])
    if not self_check['ok'] or changed or current_error:
        visits=credential.changed_visits_text(diff or {})
        if visits:
            detail='采信结果或访视窗已变化，凭证阻断：'+visits
        elif diff and diff['sections']:
            detail='封存区段已变化，凭证阻断：'+','.join(diff['sections'])
        elif current_error:
            detail='旧版凭证无法读取，已阻断并保留原文件：'+current_error
        else:
            detail='新凭证未通过自检，已保留旧版：'+'；'.join(self_check['errors'][:3])
        raise BusinessError('CREDENTIAL_BLOCKED',detail,409,
            {'blocked':True,'previous_seal':current['seal'] if current else None,
             'changed':(diff or {}).get('changed',[]),'missing':(diff or {}).get('missing',[]),
             'extra':(diff or {}).get('extra',[]),'sections':(diff or {}).get('sections',[]),
             'errors':self_check['errors']+([current_error] if current_error else [])})
    saved=store.save_credential(DB_PATH,run_id,candidate)
    return _zip_response(saved['package'],run_id,saved['seal'])

@app.get('/api/credential/{run_id}')
def credential_status(run_id:str):
    store.get(DB_PATH,run_id)
    current=store.current_credential(DB_PATH,run_id)
    history=store.credentials(DB_PATH,run_id)
    report=credential.verify_bundle(current['package']) if current else None
    return {'run_id':run_id,'current':current['seal'] if current else None,
            'seal':current['seal'] if current else None,
            'created_at':current['created_at'] if current else None,
            'history':history,
            'verify':None if report is None else {'ok':report['ok'],'errors':report['errors'],
                                                  'seal':report['seal']}}

@app.get('/api/credential/{run_id}/candidate')
def credential_candidate(run_id:str):
    """构造当前状态的候选凭证，仅供复核后替换。不改变当前凭证，不自动封存。"""
    result=store.get(DB_PATH,run_id)
    candidate=credential.build(result)
    current=store.current_credential(DB_PATH,run_id)
    diff={'changed':[],'missing':[],'extra':[],'sections':[]}
    if current is not None:
        parsed,error=credential.load_bundle(current['package'])
        if parsed is not None:
            diff=credential.compare_evidence(parsed['evidence.json'],candidate['evidence'])
    response=_zip_response(candidate['zip'],run_id,candidate['seal'])
    response.headers['X-Credential-Previous']=current['seal'] if current else ''
    response.headers['X-Credential-Changed']='yes' if (diff['changed'] or diff['missing']
        or diff['extra'] or diff['sections']) else 'no'
    response.headers['X-Credential-Changed-Visits']=changed_visits_text(diff)
    return response

@app.get('/api/credential/{run_id}/{seal}')
def credential_download(run_id:str,seal:str):
    saved=store.credential(DB_PATH,run_id,seal)
    return _zip_response(saved['package'],run_id,saved['seal'])

@app.post('/api/credential/{run_id}/replace')
async def credential_replace(run_id:str,request:Request):
    """以提交的凭证替换当前版本；不合法或与批次不一致时保留旧版并阻断。"""
    store.get(DB_PATH,run_id)
    package=await request.body()
    if not package:
        raise BusinessError('EMPTY_FILE','请提交凭证 ZIP',422)
    report=credential.verify_bundle(package,expected=store.get(DB_PATH,run_id))
    current=store.current_credential(DB_PATH,run_id)
    if not report['ok']:
        error=BusinessError('CREDENTIAL_REJECTED',
            '凭证未通过校验，已保留旧版：'+(changed_visits_text(report) or '；'.join(report['errors'])),
            409,{'blocked':True,'previous_seal':current['seal'] if current else None,
                 'changed':report['changed'],'missing':report['missing'],'extra':report['extra'],
                 'errors':report['errors']})
        raise error
    parsed,error=credential.load_bundle(package)
    if error:
        raise BusinessError('CREDENTIAL_REJECTED','凭证无法读取，已保留旧版：'+error,409,
            {'blocked':True,'previous_seal':current['seal'] if current else None,'errors':[error]})
    diff={'changed':[],'missing':[],'extra':[],'sections':[]}
    if current is not None:
        old_parsed,old_error=credential.load_bundle(current['package'])
        if old_parsed is not None:
            diff=credential.compare_evidence(old_parsed['evidence.json'],parsed['evidence.json'])
    document={'seal':report['seal'],'zip':package,'manifest':parsed['manifest.json']}
    saved=store.save_credential(DB_PATH,run_id,document)
    return {'ok':True,'run_id':run_id,'seal':saved['seal'],
            'previous_seal':current['seal'] if current else None,
            'changed':diff['changed'],'missing':diff['missing'],'extra':diff['extra'],
            'sections':diff['sections'],'changed_text':changed_visits_text(diff)}

@app.post('/api/credential/verify')
async def credential_verify(request:Request,run_id:str|None=None):
    """提交凭证 ZIP 复核；提供 run_id 时与当前批次逐访视比对。"""
    package=await request.body()
    if not package:
        raise BusinessError('EMPTY_FILE','请提交凭证 ZIP',422)
    expected=store.get(DB_PATH,run_id) if run_id else None
    report=credential.verify_bundle(package,expected=expected)
    report['changed_text']=changed_visits_text(report)
    return report
for key in MODULES:
    app.include_router(import_module(f'app.modules.{key}.handler').router)

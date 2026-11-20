"""Measure full bytes and peer limits without reading credentials or payloads into the observations."""
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.request import ProxyHandler, build_opener, Request

opener=build_opener(ProxyHandler({}))
def fetch(path):
    with opener.open('http://127.0.0.1:18080/'+path,timeout=10) as response:
        return response.read()

def numbers(path): return json.loads(fetch(path))

probe,out=Path(sys.argv[1]),Path(sys.argv[2]); out.mkdir(exist_ok=True)
(out/'linux.json').write_bytes(fetch('environment'))
size=64<<20
pattern=hashlib.sha256()
for _ in range(size//65536): pattern.update(bytes(range(256))*256)
rows=[]

def run(root,server,mode,trial):
    label=f'{server}-{mode}-{trial}'
    req={'profile':str(root/(server+'.mobileconfig')),'mode':mode,'url':f'https://relay.test:18443/{size}',
         'expectedBytes':size,'expectedSHA256':pattern.hexdigest(),'count':4,'concurrency':4,'timeoutSeconds':440,
         'testRootDER':str(root/'ca.der'),'trustRelay':True}
    request=root/'settings.json'; request.write_text(json.dumps(req)); result=out/(label+'.json'); folder=root/label; folder.mkdir()
    before=numbers('counts'); initial=numbers('progress'); samples=[]; started=time.monotonic()
    with subprocess.Popen([probe,request,result],env=dict(os.environ,RELAY_TASK_PROGRESS=str(folder))) as child:
        while child.poll() is None:
            if time.monotonic()-started>485:
                child.kill();break
            try:
                state=numbers('progress'); samples.append({'seconds':round(time.monotonic()-started,3),
                    'writes':{k:v for k,v in state['writes'].items() if k not in initial['writes']},
                    'streams':{k:v for k,v in state['streams'].items() if k not in initial['streams']},
                    'relay_cpu':state['cpu'][server]-initial['cpu'][server]})
            except OSError: samples.append({'seconds':round(time.monotonic()-started,3),'read_timeout':True})
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
        rc=child.wait()
    tasks=sorted([json.loads(p.read_bytes()) for p in folder.glob('*.json')],key=lambda t:t['elapsed'])
    (out/(label+'-progress.json')).write_text(json.dumps({'linux':samples,'apple':tasks},separators=(',',':')))
    after=numbers('counts'); report=json.loads(result.read_bytes()) if result.exists() else {}; good=sum(r.get('ok') is True for r in report.get('samples',[])); origin=after.get('download',0)-before.get('download',0); routes=after.get(server+'_tcp',0)-before.get(server+'_tcp',0)
    streams=[s for sample in samples for s in sample.get('streams',{}).values()]; gso=sorted({s['gso'] for s in streams}); wal=report.get('wall_seconds'); controls=origin==4 and ((routes==0 and mode=='direct') or (routes>0 and mode!='direct'))
    if mode=='h3': controls=controls and routes>=4
    row={'case':label,'server':server,'mode':mode,'trial':trial,'origin':origin,'relay_events':routes,'verified':good,'rc':rc,'controls':controls,'gso':gso,'seconds':wal,'within_180s':good==4 and wal is not None and wal<=180,'completed':bool(report.get('completed') and good==4 and rc==0),'task_samples':len(tasks),'os':report.get('os')}; rows.append(row);print(json.dumps(row),flush=True);(out/'summary.json').write_text(json.dumps(rows,indent=2))

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);(root/'ca.der').write_bytes(fetch('ca.der'))
    for kind in ('caddy','candidate','nogso'): (root/(kind+'.mobileconfig')).write_bytes(fetch(kind+'.mobileconfig'))
    identity=numbers('environment')
    phases=[]
    run(root,'caddy','direct',1)
    run(root,'caddy','h2',1)
    for index,arm in enumerate(os.environ['RELAY_PHASE']):
        with opener.open(Request('http://127.0.0.1:18080/advance',data=b'',method='POST'),timeout=45) as result:
            installed=json.load(result)
        assert installed=={'arm':arm,'index':index,'port':14201,'sha256':identity['caddy' if arm=='A' else 'candidate']}
        phases.append(installed); (out/'phases.json').write_text(json.dumps(phases,indent=2))
        run(root,'caddy','h3',f'{index+1}-{arm}')
    run(root,'caddy','h2',2)
assert len(rows)==7 and all(x['completed'] and x['controls'] for x in rows)

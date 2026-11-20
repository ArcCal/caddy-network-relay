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
from urllib.request import ProxyHandler, build_opener

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

def run(root,server,mode,trial,port):
    label=f'{server}-{mode}-{trial}'
    req={'profile':str(root/(server+'.mobileconfig')),'mode':mode,'url':f'https://relay.test:{port}/{size}',
         'expectedBytes':size,'expectedSHA256':pattern.hexdigest(),'count':4,'concurrency':4,'timeoutSeconds':360,
         'testRootDER':str(root/'ca.der'),'trustRelay':True}
    request=root/'settings.json'; request.write_text(json.dumps(req)); result=out/(label+'.json'); folder=root/label; folder.mkdir()
    before=numbers('counts'); initial=numbers('progress'); samples=[]; started=time.monotonic()
    with subprocess.Popen([probe,request,result],env=dict(os.environ,RELAY_TASK_PROGRESS=str(folder))) as child:
        while child.poll() is None:
            if time.monotonic()-started>415:
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
    if mode=='h3': controls=controls and bool(streams) and (server!='nogso' or gso==[False]);
    counts={k:after.get(k,0)-before.get(k,0) for k in ('legacy_accepted','legacy_handshake_error','worker_accepted','worker_handshake_error')}
    row={'port':port,'handshakes':counts,'case':label,'server':server,'mode':mode,'trial':trial,'origin':origin,'relay_events':routes,'verified':good,'rc':rc,'controls':controls,'gso':gso,'seconds':wal,'within_180s':good==4 and wal is not None and wal<=180,'completed':bool(report.get('completed') and good==4 and rc==0),'task_samples':len(tasks),'os':report.get('os')}; rows.append(row);print(json.dumps(row),flush=True);(out/'summary.json').write_text(json.dumps(rows,indent=2))

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);(root/'ca.der').write_bytes(fetch('ca.der'))
    for kind in ('caddy','candidate','nogso'): (root/(kind+'.mobileconfig')).write_bytes(fetch(kind+'.mobileconfig'))
    readers=['file','stream']
    if os.environ['RELAY_READER_REVERSE']=='true': readers.reverse()
    for index, reader in enumerate(readers):
        os.environ['RELAY_READER']=reader
        for port in ([18443,18444] if index==0 else [18444,18443]):
            run(root,'caddy','direct',f'{reader}-{port}',port)
        run(root,'caddy','h2',reader,18444)
        run(root,'caddy','h3',reader,18444)
assert len(rows)==8 and all(row['completed'] and row['controls'] for row in rows)

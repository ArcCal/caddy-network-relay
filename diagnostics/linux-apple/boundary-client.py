"""Verify actual generated transport-only profiles, both UDP directions and exact origin bytes."""
import collections
import hashlib
import json
import plistlib
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

fetch = runpy.run_path(str(Path(__file__).with_name('client.py')))['fetch']
probe, out = Path(sys.argv[1]), Path(sys.argv[2]); out.mkdir(exist_ok=True)
(out / 'linux.json').write_bytes(fetch('environment'))
rows = []
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); (root / 'ca.der').write_bytes(fetch('ca.der'))
    for kind in ('rust', 'candidate'):
        header = None
        for transport in ('h2','h3'):
            profile = root / f'{kind}-{transport}.mobileconfig'
            source_transport = 'h2' if transport == 'h3' else 'h3'
            source = root / f'{kind}-{source_transport}-seed-for-{transport}.mobileconfig'
            original = fetch(f'{kind}-{source_transport}.mobileconfig')
            source.write_bytes(original)
            subprocess.run([sys.executable, 'profile-tool/tools/select-apple-relay-transport.py',
                            transport, source, profile], check=True)
            expected = plistlib.loads(original)
            seed_hop = expected['PayloadContent'][0]['Relays'][0]
            seed_key = 'HTTP' + source_transport[-1] + 'RelayURL'
            select_key = 'HTTP' + transport[-1] + 'RelayURL'
            assert seed_key in seed_hop and select_key not in seed_hop
            seed_hop[select_key] = seed_hop.pop(seed_key)
            assert plistlib.loads(profile.read_bytes()) == expected and source.read_bytes() == original
            assert profile.stat().st_mode & 0o777 == 0o600
            reference = plistlib.loads(fetch(f'{kind}-{transport}.mobileconfig'))
            assert reference['PayloadContent'][0]['Relays'][0] == seed_hop
            relay = plistlib.loads(profile.read_bytes())['PayloadContent'][0]['Relays'][0]
            expected_key = 'HTTP2RelayURL' if transport=='h2' else 'HTTP3RelayURL'
            assert {k for k in relay if k in ('HTTP2RelayURL','HTTP3RelayURL')}=={expected_key}
            assert 'Authorization' in relay['AdditionalHTTPHeaderFields']
            if header is not None: assert relay['AdditionalHTTPHeaderFields']==header
            header = relay['AdditionalHTTPHeaderFields']
            for send,recv,tail in ((62,62,33),(63,63,33),(63,63,211),(64,63,211),(64,64,33)):
                variants = ('auto','direct') if kind=='rust' and transport=='h2' and send==63 else ('auto',)
                for mode in variants:
                    for write in (('one','split') if send==63 else ('one',)):
                        label = f'{kind}-{transport}-{mode}-{send}-{recv}-{tail}-{write}'
                        payload = bytearray((n*13+7)&255 for n in range(send)); payload[:5]=b'RLYU'+bytes([recv]); payload[-1]=tail
                        reply = bytearray((n*17+23)&255 for n in range(recv)); reply[-1]=tail
                        request={'profile':str(profile),'mode':mode,'operation':'udp','url':f'https://relay.test:18553/{send}/{recv}/{tail}/{write}',
                                 'expectedBytes':recv,'expectedSHA256':hashlib.sha256(reply).hexdigest(),'count':1,'concurrency':1,
                                 'timeoutSeconds':10,'testRootDER':str(root/'ca.der'),'trustRelay':True}
                        settings=root/'settings.json'; settings.write_text(json.dumps(request)); result=out/(label+'.json')
                        before=collections.Counter(json.loads(fetch('counts'))); proc=subprocess.run([probe,settings,result],capture_output=True,timeout=150)
                        report=json.loads(result.read_bytes()) if result.exists() else {}; after=collections.Counter(json.loads(fetch('counts')))
                        def delta(key):return after[key]-before[key]
                        origin=delta('udp'); exact=delta('fixture_'+hashlib.sha256(payload).hexdigest()); route=delta(kind+'_udp')
                        good=proc.returncode==0 and report.get('completed') is True and origin==exact==1
                        missing=(proc.returncode==2 and report.get('ready') is True and any(x.get('sent') is True for x in report.get('samples',[])) and origin==exact==0)
                        control=(mode=='direct' and route==0) or (mode!='direct' and route>0)
                        row={'case':label,'write':write,'server':kind,'profile':transport,'mode':mode,'sent':send,'reply':recv,'tail':tail,'os':report.get('os'),
                             'rc':proc.returncode,'origin':origin,'exact_origin':exact,'relay_events':route,'delivered':good,'missing_before_origin':missing,
                             'classified':bool(control and (good or (send==63 and mode=='auto' and transport=='h2' and missing) or (write=='split' and proc.returncode==2 and origin>=0)))}
                        rows.append(row);print(json.dumps(row),flush=True);(out/'boundary.json').write_text(json.dumps(rows,indent=2))
assert len(rows)==32 and all(r['classified'] for r in rows)

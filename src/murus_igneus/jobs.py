"""Single asynchronous maintenance job with bounded local log. SPDX-License-Identifier: MIT."""
from pathlib import Path
import secrets,subprocess,threading,time
try:
    from .migration import Error
except ImportError:
    from migration import Error
LOCK=threading.RLock();JOB=None

def busy():return bool(JOB and JOB['state']=='running')
def status():
    with LOCK:
        if not JOB:return None
        item={k:v for k,v in JOB.items() if k!='path'};p=Path(JOB['path'])
        if p.exists():
            with p.open('rb') as f:f.seek(max(0,p.stat().st_size-40000));item['log']=f.read().decode(errors='replace')
        return item

def start(name,action):
    global JOB
    with LOCK:
        if busy():raise Error('Operazione già in corso')
        ident=secrets.token_hex(16);path=Path('/run/murus-igneus');path.mkdir(mode=0o700,exist_ok=True)
        JOB={'id':ident,'name':name,'state':'running','started':time.time(),'path':str(path/'maintenance.log')}
        Path(JOB['path']).write_text('')
        def worker():
            try:
                with Path(JOB['path']).open('a') as log:action(log)
                with LOCK:JOB['state']='succeeded'
            except Exception as e:
                with Path(JOB['path']).open('a') as log:log.write('\nERRORE: '+str(e)+'\n')
                with LOCK:JOB['state']='failed'
        threading.Thread(target=worker,daemon=True).start();return {'id':ident}

def run(args,log,data=None,timeout=1800):
    r=subprocess.run(args,input=data,text=True,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
    log.flush()
    if r.returncode:raise Error('Comando fallito: '+args[0]+' ('+str(r.returncode)+')')


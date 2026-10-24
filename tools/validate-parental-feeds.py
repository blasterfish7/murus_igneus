"""Check the actual allowlisted category downloads; keep data out of the image. SPDX-License-Identifier: MIT."""
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/murus_igneus'))
import parental

rows=[]
with tempfile.TemporaryDirectory(prefix='murus-feed-qa-') as directory:
    for category in parental.FEEDS:
        parental.update_feed(directory,category)
        deadline=time.monotonic()+60
        while parental.TASK.status()['state']=='running' and time.monotonic()<deadline:time.sleep(.1)
        result=parental.TASK.status();assert result['state']=='succeeded',result
        record=json.loads(parental.feed_path(category,directory).read_text())
        rows.append({k:record[k] for k in ('category','updated','source','license','sha256')})
        rows[-1]['domains']=len(record['domains'])
        print(category,len(record['domains']),record['sha256'],flush=True)
(ROOT/'dist').mkdir(exist_ok=True)
(ROOT/'dist/parental-feed-qa.json').write_text(json.dumps({'success':True,'feeds':rows,'scope':'Real HTTPS downloads and strict format validation, not a category efficacy benchmark.'},indent=2))

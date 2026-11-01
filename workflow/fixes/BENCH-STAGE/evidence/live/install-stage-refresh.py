from pathlib import Path
import json,subprocess,hashlib,datetime
root=Path('/home/hami/phorvex-benchmark');release=root/'releases/stage-bot-348c1c7a';data=root/'stage-data';journal=data/'observer/ef94-1a70/compressed-evidence.db';out=data/'deployment/bot-348c1c7a'
assert json.loads((data/'mathlab/stage.json').read_text())['brain']['git_sha']=='ef94fad362dabb51469211388ef80cdfa6eee1d4'
assert journal.exists()
units=Path.home()/'.config/systemd/user';units.mkdir(parents=True,exist_ok=True)
service=units/'phorvex-stage-endpoint-refresh.service';timer=units/'phorvex-stage-endpoint-refresh.timer'
assert not service.exists() and not timer.exists(),'preserve existing unowned units'
service.write_text('[Unit]\nDescription=Refresh qualified source-bound stage brain benchmark data\nAfter=network-online.target\n\n[Service]\nType=oneshot\nWorkingDirectory='+str(release)+'\nEnvironment=PATH=/usr/local/bin:/usr/bin:/bin\nEnvironment=PYTHONDONTWRITEBYTECODE=1\nExecStart='+str(root/'runtime/python/bin/python')+' '+str(release/'benchmark/worker/endpoint_refresh.py')+' --data '+str(data)+' --repo '+str(root/'operator-refactored')+' --policy phorvex-staging-demo/stage-bench-defense --journal '+str(journal)+' --slo-target .9 --window 600 --lookback 600 --worth-threshold 0 --ticks 64 --timeout 900\nTimeoutStartSec=930\nUMask=0077\nNoNewPrivileges=true\n')
timer.write_text('[Unit]\nDescription=Periodic refresh of stage brain benchmark dataset\n\n[Timer]\nOnActiveSec=10s\nOnUnitInactiveSec=180s\nAccuracySec=10s\nUnit=phorvex-stage-endpoint-refresh.service\n\n[Install]\nWantedBy=timers.target\n')
subprocess.run(['systemctl','--user','daemon-reload'],check=True);subprocess.run(['systemctl','--user','enable','--now',timer.name],check=True)
receipt={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'348c1c7a64256e945f10077b3eb8e2a6cca107ea','journal':str(journal),'service_sha256':hashlib.sha256(service.read_bytes()).hexdigest(),'timer_sha256':hashlib.sha256(timer.read_bytes()).hexdigest(),'scope':'read-only stage sync/export/normalize; local bounded cache publication; no automatic physical calibration','cadence_seconds_after_completion':180,'settings':{'window':600,'lookback':600,'slo_target':.9,'worth_threshold':0,'ticks':64},'pending_initial_history':'A first refresh may correctly remain BLOCKED until64eligible sealedticks after600seconds observedhistory'}
(out/'refresh-service-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

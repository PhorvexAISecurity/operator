import datetime,hashlib,json,pathlib,subprocess
root=pathlib.Path('/home/hami/phorvex-benchmark');release=root/'releases/stage-selfserve-225877a8ecb4';source='225877a8ecb4c11eb39980ba932c114f7a8068a4';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();manifest=release/'reviewed-source-manifest.json';assert sha(manifest)=='58d20116ecb6f4ef601da836e0033b8ce63218159226de4ee742c95390ef5cff';rows=json.loads(manifest.read_text())['paths'];assert len(rows)==169
for row in rows:assert sha(release/row['path'])==row['sha256'],row['path']
assert json.loads((release/'release-origin.json').read_text())['commit']==source
installer=root/'stage-data/deployment/selfserve-225877a8ecb4/receipt.json';receipt=json.loads(installer.read_text());assert sha(installer)=='fdd4698ba485c34f7f8077a2ee78aef825c2d0067567ec67ca97d0e96150cb15';units=pathlib.Path.home()/'.config/systemd/user';actual={}
for name,expected in receipt['proposed_unit_hashes'].items():
 assert sha(units/name)==expected,name
 raw=subprocess.run(['systemctl','--user','show',name,'--property=WorkingDirectory,ActiveState,SubState,MainPID,ExecMainStatus,Result'],capture_output=True,text=True,check=True,timeout=10).stdout
 actual[name]=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
for name in ['phorvex-stage-observer.service','phorvex-stage-reconcile.service','phorvex-stage-endpoint-refresh.service']:assert actual[name]['WorkingDirectory']==str(release)
assert actual['phorvex-benchmark-bot.service']['WorkingDirectory']==str(release/'benchmark/bot')
pin=json.loads((root/'stage-data/mathlab/stage.json').read_text());assert pin['brain']['git_sha']=='a5f32f9dba5ed6e756f11b73ece968d54805c3e2';assert pin['study_engine_lane']=='native-stage-image'
print(json.dumps({'verdict':'PASS_INSTALLED_CONTENT_AND_UNIT_BINDING','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':source,'release':str(release),'runtime_manifest_sha256':sha(manifest),'runtime_files_verified':len(rows),'unit_hashes_verified':receipt['proposed_unit_hashes'],'units_observed':actual,'native_capture_source':pin['brain']['git_sha'],'native_capture_digest':pin['brain']['image_digest'],'native_replay_binary_sha256':pin['replay']['binary_sha256'],'scope':'Read-only file hashing/systemctl show only. Unit activity may be temporarily paused by already authorized acceptance; no bot or cluster mutation, no terminal benchmark claim.'},indent=2))

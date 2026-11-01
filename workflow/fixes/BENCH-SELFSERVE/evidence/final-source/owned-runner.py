import datetime, json, os, pathlib, signal, subprocess, sys, time
config_path = pathlib.Path(sys.argv[1]).resolve()
config = json.loads(config_path.read_text())
status_path = pathlib.Path(config['status'])
log_path = pathlib.Path(config['log'])
started = time.monotonic()
status = {'state': 'RUNNING', 'pid': os.getpid(), 'source_sha': config['source_sha'],
          'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'results': []}
active = None

def save():
    status['elapsed_seconds'] = round(time.monotonic() - started, 3)
    temporary = status_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(status, indent=2) + '\n')
    temporary.replace(status_path)

def stop_active():
    if active is not None and active.poll() is None:
        try: os.killpg(active.pid, signal.SIGINT)
        except ProcessLookupError: return
        try: active.wait(timeout=15)
        except subprocess.TimeoutExpired:
            try: os.killpg(active.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            active.wait()

def terminated(signum, frame):
    stop_active()
    status.update(state='INTERRUPTED', signal=signum, exit_code=128+signum)
    save()
    raise SystemExit(128+signum)

signal.signal(signal.SIGTERM, terminated)
signal.signal(signal.SIGINT, terminated)
log_path.parent.mkdir(parents=True, exist_ok=True)
status_path.parent.mkdir(parents=True, exist_ok=True)
save()
try:
    with log_path.open('w') as stream:
        stream.write(config['description'] + '\n'); stream.flush()
        env = dict(os.environ); env.update(config['env'])
        for step in config['steps']:
            remaining = config['total_timeout_seconds'] - (time.monotonic() - started)
            if remaining <= 0:
                status.update(state='TIMEOUT', exit_code=124); save(); break
            stream.write('START '+step['name']+'\n'); stream.flush()
            active = subprocess.Popen(step['command'], cwd=config['cwd'], env=env,
                                      stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            status.update(step=step['name'], child_pid=active.pid); save()
            try:
                exit_code = active.wait(timeout=min(step['timeout_seconds'], remaining))
                timed_out = False
            except subprocess.TimeoutExpired:
                stop_active(); exit_code = 124; timed_out = True
            status['results'].append({'name':step['name'], 'exit_code':exit_code, 'timed_out':timed_out})
            stream.write('END '+step['name']+' exit='+str(exit_code)+'\n'); stream.flush()
            active = None
            save()
            if exit_code:
                status.update(state='TIMEOUT' if timed_out else 'FAILED', exit_code=exit_code); save(); break
        else:
            status.update(state='DONE', exit_code=0); save()
except BaseException as error:
    if status['state'] == 'RUNNING':
        stop_active()
        status.update(state='ERROR', exit_code=1, error=type(error).__name__+': '+str(error)); save()
    raise
finally:
    status['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()

import contextlib,importlib.machinery,importlib.util,io,json,pathlib,signal,tempfile,time,types,unittest
from unittest.mock import patch
SRC=pathlib.Path(__file__).resolve().parents[1]/'phvx-runner-maintenance'
loader=importlib.machinery.SourceFileLoader('maintenance',str(SRC));spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m)

def setUpModule():
 global profile_patch
 profile_patch=patch.object(m.profiles_lib,'profiles',return_value=m.profiles_lib.APPROVED)
 profile_patch.start()
def tearDownModule():profile_patch.stop()

class Proof(unittest.TestCase):
 def evidence(self):
  t=time.time();return {'started_at':t-1,'finished_at':t,'idle':True,'repositories':[{'name':r,'viewerPermission':'ADMIN'} for r in m.REPOS],'checks':[{'repository':r,'query_status':s,'runs':[]} for r in m.REPOS for s in ('queued','in_progress')]}
 def check(self,data,**kwargs):
  with patch.object(m.sys,'stdin',io.StringIO(json.dumps(data)+'\n')),patch.object(m.select,'select',return_value=([True],[],[])),contextlib.redirect_stdout(io.StringIO()):m.proof(**kwargs)
 def test_complete_fresh_gate(self):self.check(self.evidence())
 def test_missing_repo_status_refused(self):
  e=self.evidence();e['checks'].pop()
  with self.assertRaises(RuntimeError):self.check(e)
 def test_busy_never_authorizes_planned_stop(self):
  e=self.evidence();e['idle']=False;e['checks'][0]['runs']=[{'id':42,'status':'queued'}]
  with self.assertRaises(RuntimeError):self.check(e)
  self.check(e,allow_busy=True)
 def test_stale_refused(self):
  e=self.evidence();e['finished_at']-=10;e['started_at']-=10
  with self.assertRaises(RuntimeError):self.check(e)
 def test_pause_requires_new_measurement(self):
  e=self.evidence()
  with self.assertRaises(RuntimeError):self.check(e,after=time.time())
 def test_admin_visibility_refused(self):
  e=self.evidence();e['repositories'][0]['viewerPermission']='WRITE'
  with self.assertRaises(RuntimeError):self.check(e)

class HoldDispatch(unittest.TestCase):
 def run_main(self,action,nonce='correct',evidence=None):
  evidence=self.evidence if evidence is None else evidence
  with patch.object(m.sys,'argv',['maintenance',action,nonce]),patch.object(m.sys,'stdin',io.StringIO(json.dumps(evidence)+'\n')),patch.object(m.select,'select',return_value=([True],[],[])),contextlib.redirect_stdout(io.StringIO()):
   m.main()
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=pathlib.Path(self.temp.name);self.run=self.root/'run';self.run.mkdir()
  self.hold=self.root/'hold';self.hold.write_text(json.dumps({'owner':'runner-speed-20261014','nonce':'correct'}))
  (self.run/'offline-fence').write_text('{}')
  self.evidence=Proof().evidence();self.evidence['idle']=False
  next(c for c in self.evidence['checks'] if c['repository']=='operator' and c['query_status']=='queued')['runs']=[{'id':42,'status':'queued'}]
  original_stat=pathlib.Path.stat;original_read=pathlib.Path.read_text
  def stat(path,*args,**kwargs):
   value=original_stat(path,*args,**kwargs)
   return types.SimpleNamespace(st_uid=0,st_mode=value.st_mode) if path==self.run else value
  def read(path,*args,**kwargs):
   return '7089cf7bcdeb41869b950cf23aefff81' if str(path)=='/etc/machine-id' else original_read(path,*args,**kwargs)
  self.commands=unittest.mock.Mock();self.idle=unittest.mock.Mock()
  for mock in [patch.object(m,'RUN',self.run),patch.object(m.os,'geteuid',return_value=0),patch.object(pathlib.Path,'stat',stat),patch.object(pathlib.Path,'read_text',read),patch.object(m.profiles_lib,'HOLD',self.hold),patch.object(m.profiles_lib,'trusted_json',side_effect=lambda path:json.loads(path.read_text())),patch.object(m.profiles_lib,'listener_count',return_value=1),patch.object(m,'local_idle',self.idle),patch.object(m,'command',self.commands)]:
   mock.start();self.addCleanup(mock.stop)
 def test_queued_hold_release_then_start_only_recovery_through_main(self):
  self.run_main('release')
  self.assertFalse(self.hold.exists());self.commands.assert_not_called();self.idle.assert_not_called()
  self.run_main('recover-fence')
  self.assertFalse((self.run/'offline-fence').exists())
  self.idle.assert_called_once_with(False,allow_unmatched=True)
  self.assertEqual([call.args[0] for call in self.commands.call_args_list],[['systemctl','start','containerd.service'],['systemctl','start','docker.service'],['systemctl','start',m.profiles_lib.APPROVED[0]['unit']]])
 def test_wrong_nonce_refused_and_recovery_keeps_hold(self):
  with self.assertRaisesRegex(RuntimeError,'nonce mismatch'):self.run_main('release','wrong')
  self.assertTrue(self.hold.exists())
  with self.assertRaisesRegex(RuntimeError,'Persistent rescale hold'):self.run_main('recover-fence')
  self.commands.assert_not_called();self.assertTrue(self.hold.exists())
 def test_queued_work_still_refuses_drain_stop_and_set_hold(self):
  for action in ('drain','stop-runner','stop-docker','restart-docker','restart-containerd','hold'):
   with self.subTest(action=action),self.assertRaisesRegex(RuntimeError,'busy API proof'):self.run_main(action)
  self.commands.assert_not_called();self.idle.assert_not_called();self.assertTrue(self.hold.exists())
 def test_release_still_requires_complete_fresh_admin_proof(self):
  for mutate in (lambda e:e['checks'].pop(),lambda e:e['repositories'][0].update(viewerPermission='READ'),lambda e:e.update(finished_at=time.time()-10)):
   e=Proof().evidence();mutate(e)
   with self.assertRaises(RuntimeError):self.run_main('release',evidence=e)
  self.assertTrue(self.hold.exists());self.commands.assert_not_called()

class Drain(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.run=pathlib.Path(self.tmp.name);self.clock=0;self.state='S';self.signals=[]
  self.listener={'pid':100,'ppid':200,'start':123,'uid':1000,'state':'S','exe':str(m.ROOT/'bin/Runner.Listener'),'comm':'Runner.Listener','cgroup':'0::/system.slice/'+m.UNIT}
  def process(pid):
   if pid==100:return {**self.listener,'state':self.state}
   return {'pid':pid,'uid':0,'start':456 if pid==300 else 555}
  def command(args,timeout=8):
   if args[0]=='systemd-run' and '--watchdog' in args:
    path=pathlib.Path(args[args.index('--watchdog')+1]);data=json.loads(path.read_text());data.update(phase='armed',watchdog_pid=300,watchdog_start=456);m.write_state(path,data)
   return '300'
  def send(fd,sig):
   self.signals.append((fd,sig))
   if sig==signal.SIGSTOP:self.state='T'
   if sig==signal.SIGCONT:self.state='S'
  def sleep(n):self.clock+=n
  for p in [patch.object(m,'RUN',self.run),patch.object(m,'proc',side_effect=process),patch.object(m,'local_idle',return_value=[self.listener]),patch.object(m,'command',side_effect=command),patch.object(m.os,'pidfd_open',side_effect=lambda pid:pid),patch.object(m.os,'close'),patch.object(m.signal,'pidfd_send_signal',side_effect=send),patch.object(m.select,'select',return_value=([],[],[])),patch.object(m.time,'monotonic',side_effect=lambda:self.clock),patch.object(m.time,'sleep',side_effect=sleep),patch.object(m,'log')]:p.start();self.addCleanup(p.stop)
 def drain(self):
  with contextlib.redirect_stdout(io.StringIO()):m.drain()
 def test_before_shutdown_abort_resumes_and_clears_fence(self):
  with patch.object(m,'proof',side_effect=RuntimeError('busy')):
   with self.assertRaises(RuntimeError):self.drain()
  self.assertEqual(self.signals,[(100,signal.SIGSTOP),(100,signal.SIGCONT)]);self.assertFalse((self.run/'offline-fence').exists())
 def test_after_shutdown_race_preserves_recovery_fence(self):
  with patch.object(m,'proof',return_value={'finished_at':time.time()}),patch.object(m,'processes',return_value=[{'comm':'Runner.Worker'}]):
   with self.assertRaises(RuntimeError):self.drain()
  self.assertTrue((self.run/'offline-fence').is_file());self.assertEqual(self.signals,[(100,signal.SIGSTOP),(100,signal.SIGINT),(100,signal.SIGCONT)])
 def test_timeout_preserves_fence_and_never_forces_kill(self):
  with patch.object(m,'proof',return_value={'finished_at':time.time()}),patch.object(m,'processes',return_value=[{'comm':'Runner.Listener'}]):
   with self.assertRaises(RuntimeError):self.drain()
  self.assertTrue((self.run/'offline-fence').exists());self.assertNotIn((100,signal.SIGKILL),self.signals)
 def test_expired_pause_cannot_send_int_after_resume(self):
  def expire(**kwargs):self.clock+=15;return {'finished_at':time.time()}
  with patch.object(m,'proof',side_effect=expire):
   with self.assertRaises(RuntimeError):self.drain()
  self.assertNotIn((100,signal.SIGINT),self.signals);self.assertFalse((self.run/'offline-fence').exists())

class Watchdog(unittest.TestCase):
 def test_armed_watchdog_survives_delayed_controller_then_death(self):
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'state';m.write_state(path,{'phase':'arming'});clock=[0.0];sent=[]
   def process(pid):return {'uid':1000 if pid==100 else 0,'start':123 if pid==100 else 456,'exe':str(m.ROOT/'bin/Runner.Listener'),'state':'S'}
   def select_fd(read,*args):return ([200] if read==[200] and clock[0]>=10 else [],[],[])
   def sleep(n):clock[0]+=n
   with patch.object(m,'proc',side_effect=process),patch.object(m.os,'pidfd_open',side_effect=lambda pid:pid),patch.object(m.os,'close'),patch.object(m.select,'select',side_effect=select_fd),patch.object(m.time,'monotonic',side_effect=lambda:clock[0]),patch.object(m.time,'sleep',side_effect=sleep),patch.object(m.signal,'pidfd_send_signal',side_effect=lambda fd,sig:sent.append((fd,sig))),patch.object(m,'log'):
    m.watchdog(path,100,123,200,456)
   self.assertGreaterEqual(clock[0],10);self.assertEqual(sent,[(100,signal.SIGCONT)]);self.assertEqual(json.loads(path.read_text())['phase'],'expired')

if __name__=='__main__':unittest.main(verbosity=2)

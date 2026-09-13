import sys, unittest, time
from pathlib import Path
from unittest.mock import patch
root=Path('/home/mehrdad/operator-workers')
sys.path.insert(0,str(root/'workflow/tools/tests'))
import test_workers as T
w=T.workers
class ReceiptRace(T.RunnerTestCase):
 def test_real_completed_wrapper_receipt_arrives_after_initial_read(self):
  self.register();self.enqueue();self.pass_once('sleep')
  self.wait_for_cli('w1:j1')
  original=w.read_json; gated=[False]
  def read(path):
   if Path(path).name=='receipt.json' and not gated[0]:
    gated[0]=True
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
     value=original(path)
     child=original(Path(path).parent/'child.json')
     if value and not w.process_alive(child.get('pid'),child.get('pid_start')):break
     time.sleep(.01)
    else:self.fail('actual wrapper did not complete within test bound')
    return {} # receipt was absent at the first read; the wrapper finishes before liveness read
   return original(path)
  with patch.object(w,'read_json',side_effect=read):state=self.pass_once('sleep')
  job=state['jobs']['w1:j1']
  print('ACTUAL_JOB',job['state'],job.get('reason'))
  self.assertEqual(job['state'],'done',job.get('reason'))
if __name__=='__main__':unittest.main(verbosity=2)

import reset
import time
import os

def unpack():
  print('unpacking',end='\r')
  reset.reset(printable=False)
  print('unpacking.',end='\r')
  time.sleep(0.8)
  print('unpacking..',end='\r')
  time.sleep(0.6)
  print('unpacking...',end='\r')
  time.sleep(1.4)
  print('unpacking complete.')

def ispacked() -> bool:
  if os.path.exists('debug.conf'): 
    os.remove('debug.conf')
    return True
  return False

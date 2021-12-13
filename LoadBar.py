from time import sleep
from os import get_terminal_size

TIME_FOR_EACH_LOGIN = 1.6

def loadbar(iteration, total, prefix='', i_end='\r', suffix='', decimals=1, length=100, fill='#'):
	percent = ('{0:.' + str(decimals) + 'f}').format(100 * (iteration/float(total)))
	filledLength = int(length * iteration // total)
	bar = fill * filledLength + '-' * (length - filledLength)
	print(f'\r{prefix}<{bar}> {percent}% {suffix}', end=i_end)


def runLB(i_prefix, i_suffix, i_length, i_items, sl_time):
  loadbar(0, i_length, prefix=i_prefix, i_end='\r', suffix=i_suffix, length=i_length)
  for i, item in enumerate(i_items):
    sleep(sl_time)
    loadbar(i + 1, i_length, prefix=i_prefix, suffix=i_suffix, length=i_length)

  
def final(i_prefix, i_suffix, i_length, i_items):
  loadbar(len(i_items), i_length, prefix=i_prefix, i_end='', suffix=i_suffix,length=i_length)


def exe():
  columns, _ = get_terminal_size()
  max = columns - 25 # 25=sizeof('<>'+prc+login+return)+1
  items = list(range(0,max))
  l = len(items)
  # will always take 5.5 seconds to check password
  sleep_time = TIME_FOR_EACH_LOGIN / max
  runLB('', 'Login: Unknown', l, items, sleep_time)
  final('', 'Login: ', l, items)


def writeResult(isSuccessful):
  if isSuccessful:
    print('Success')
  else:
    print('Failed ')
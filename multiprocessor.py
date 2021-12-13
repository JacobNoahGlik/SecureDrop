import multiprocessing
import LoadBar
from HashPasswords import pass_compare_with_pickle
import time
import socket

def authenticate_login(pswd, sal, pep, file, email):
  print('Creating login token...')
  __name__ = "__main__"
  if __name__ == "__main__":
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    p1 = multiprocessing.Process(target=LoadBar.exe, args=[])
    p2 = multiprocessing.Process(target=pass_compare_with_pickle, args=(pswd, sal, pep, file, email, return_dict))
    p1.start()
    p2.start()
    p1.join()
    p2.join()

  status, name, email = return_dict.values()[0]
  LoadBar.writeResult(status)
  return status, name, email



def receiveFileTimeout(server, timeout):
  __name__ = '__main__'
  if __name__ == '__main__':
    run_flag = multiprocessing.Value('I', True)
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    print_time = multiprocessing.Process(target=action, args=(run_flag,timeout))
    print_time.start()

    request_connection = multiprocessing.Process(target=timer, args=(run_flag, server, timeout, return_dict))
    request_connection.start()

    print_time.join()
    request_connection.join()

    if run_flag.value:
      return return_dict[0]
    return None

def action(run_flag, max):
  while run_flag.value and max > 0:
    print(f'Returning to main menu in: {max:.2f} seconds', end='\r')
    time.sleep(0.099)
    max -= 0.1
  print(f'Returning to main menu in: 0.00 seconds')


def timer(run_flag, server, timeout, return_dict):
  server.settimeout(timeout)
  try:
    # turn on listener
    server.listen()
    run_flag.value = False
    # incoming request to transfer file
    return_dict[0] = server.accept()
  except socket.timeout:
    run_flag.value = False
    print("\nServer timed out. \nReturning to SecureDrop menu.\n")
    return
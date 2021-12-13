import os
import FileCredibility

PYTHON_FILES = ['certificate_authority.py', 'ECDH.py', 'EncMsg.py', 'encryption.py', 'FileCredibility.py', 'HashPasswords.py', 'img.py', 'LoadBar.py', 'multiprocessor.py', 'receiver.py', 'reset.py', 'secureDrop.py',  'sender.py']

FILES_TO_REMOVE = ['contacts.txt', 'sym_file.encoded', 'r.pub', 'r.sig', 's.pub', 's.sig']

CERTIFICATE_FILES = ['ca.pri', 'ca.pub']

SELF_IMG_FILES = ['img_center.txt', 'img_long_space.txt', 'img_long.txt']

def reset(printable=True):
  files = os.listdir('./')

  for file in files:
    if file.endswith(".zok") or file.endswith(".encrypted"):
      os.remove(file)

  for file in FILES_TO_REMOVE:
    try:
      os.remove(file)
    except:
      pass

  FileCredibility.gen_dependencies_key()
  if not os.path.exists('dependencies.enc'):
    with open('dependencies.enc','w'): pass
  with open('dependencies.enc',"r+") as file:
    file.truncate(0)
  FileCredibility.updateFiles(CERTIFICATE_FILES + PYTHON_FILES + SELF_IMG_FILES)

  if printable:
    print("reset")

if __name__ == '__main__':
  reset()
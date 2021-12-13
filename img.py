from os import get_terminal_size
CENTER_SIZE = 60
LONG_SIZE = 100
LONG_SPACE_SIZE = 109


def bye():
  #print(" ____ _  _,____, \n(-|__|-\_/(-|_,  \n _|__) _|, _|__,")
  pass

def out():
  max_width = get_terminal_size()[0]
  if max_width > LONG_SPACE_SIZE:
    out_long_space()
  elif max_width > LONG_SIZE:
    out_long()
  else:
    out_center()


def padding(size, max_width):
  numSpaces = (max_width - size) //2
  return ' ' * numSpaces


def out_center():
  with open("img_center.txt", 'r') as img_file:
    line = img_file.readline()[:-1]
    if not line:
      return
    while line:
      max_width = get_terminal_size()[0]
      if max_width > CENTER_SIZE:
        print(padding(CENTER_SIZE, max_width), line)
      else:
        print(line[:(get_terminal_size()[0])]) # cut off extra chars by getting terminalSize
      line = img_file.readline()[:-1]


def out_long_space():
  with open("img_long_space.txt", 'r') as img_file:
    line = img_file.readline()[:-1]
    if not line:
      return
    while line:
      max_width = get_terminal_size()[0]
      if max_width > LONG_SPACE_SIZE:
        print(padding(LONG_SPACE_SIZE, max_width), line)
      else:
        print(line[:(get_terminal_size()[0])]) # cut off extra chars by getting terminalSize
      line = img_file.readline()[:-1]

  
def out_long():
  with open("img_long.txt", 'r') as img_file:
    line = img_file.readline()[:-1]
    if not line:
      return
    while line:
      max_width = get_terminal_size()[0]
      if max_width > LONG_SIZE:
        print(padding(LONG_SIZE, max_width), line)
      else:
        print(line[:(get_terminal_size()[0])]) # cut off extra chars by getting terminalSize
      line = img_file.readline()[:-1]
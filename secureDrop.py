# COMP2300 Secure Drop Project - A secure version of airdrop
# Team members:
# Jacob Glik
# Peyton Somerville


import os
import stdiomask
from cryptography.fernet import Fernet
import encryption
from os.path import exists
from inspect import currentframe, getframeinfo
import HashPasswords
import receiver
import sender
import img
import multiprocessor
import FileCredibility
import unpack



def init():
  if unpack.ispacked():
    unpack.unpack()

  print('')
  FileCredibility.VerifyFiles()
  
  img.out() # print SecureDrop logo

  if getNumUsers() == 0:
    print("No users are registered with this client.")
    c = input("Do you want to register a new user (y/n)? ")
    while 'n' != c != 'y' and 'N' != c != 'Y':
      c = input("Do you want to register a new user (y/n)? ")

    if(c == 'n'):
      img.bye()
      leave(False)
    else:
      registerUser()


def check_keys_error():
  if not keysExist():
    leave(True)
    Error100(getframeinfo(currentframe()))
    quit()


def calcNumContacts():
  FileCredibility.fullStop("contacts.txt")
  with open("contacts.txt", "r") as fContacts:
    line = fContacts.readline()
    if(not line):
      return 0
    
    counter = 0
    while(line):
      counter = counter + 1
      line = fContacts.readline()
  
  return int(counter / 2)



def registerUser():
  tempFile = input("Enter Full Name: ") + '\n'
  tempFile += input("Enter Email Address: ").lower()

  numTries = 3
  while(numTries > 0):
    print("Password must:\n\tBE:  \t8 to 25 chars\n\tHAVE:\tAt least one uppercase letter\n\tHAVE:\tAt least one lowercase letter\n\tHAVE:\tAt least one diget")

    pswd1, len_and_contains_up_low_dig = encryption.calculateKey(stdiomask.getpass(prompt='Enter Password: ').encode())

    if not len_and_contains_up_low_dig:
      print('That password is missing or failing one or more of the requirements...\n')
      continue

    
    if pswd1 != encryption.calculateKey(stdiomask.getpass(prompt='Re-Enter Password: ').encode())[0]:
      numTries = numTries - 1
      if (numTries > 0):
        print("Passwords do not match. Try again.")
      else:
        print("Too many mismatched password attempts. Exiting SecureDrop.")
        img.bye()
        leave(False)
      continue
    
    break

  print("Passwords match")
  salt, pepper, pickle = HashPasswords.condiments()
  bytes_object = encryption.encrypt_bytes(tempFile.encode(), HashPasswords.calcMaster(pswd1, salt, pepper, pickle))
  user_file = 'userData.encrypted'
  with open(user_file, 'wb') as uf:
    uf.write(bytes_object)
  FileCredibility.updateFiles([user_file])

  print("User registered.\n")

  
  
def login():
  email = ""
  numGuesses = 5
  sal, pep = HashPasswords.getCondiments()

  files = ['pickle.encrypted', 'userData.encrypted', 'userData.psw']
  for file in files:
    FileCredibility.fullStop(file)

  curHash = HashPasswords.calcPeperHash('pswd'.encode(), sal, pep)
  print('\n*Email is NOT case-sensitive*',end='')
  while (numGuesses > 0):
    email = input("\nEnter Email Address: ")
    if email.lower() == 'quit':
      inp = input("You enterd " + email + " ... are you trying to quit the program? (y/n) ")
      while inp != 'n' and inp != 'y' :
        print(inp + " is not 'y' or 'n'")
        inp = input("You enterd " + email + " ... are you trying to quit the program? (y/n) ")
      if inp == 'y':
        img.bye()
        leave(False)

    usrin = encryption.calculateKey(stdiomask.getpass(prompt='Enter Password: ').encode())[0]
    login_success, og_name, og_email = multiprocessor.authenticate_login(usrin, sal, pep, 'userData', email.lower())
    if not login_success:
      numGuesses -= 1
      if (numGuesses > 0):
        print("Incorrect email or password, please try again.")
      else:
        print("Too many incorrect email and password attempts. Exiting SecureDrop.")
        img.bye()
        leave(False)
      continue

    
    curHash = HashPasswords.calcPeperHash(usrin, sal, pep)
    break

  return curHash, og_name, og_email
    


def helpCommands():
  print("\t\"add\" \t\t-> \tAdd a new contact")
  print("\t\"remove\" \t-> \tRemove a new contact by name")
  print("\t\"list\" \t\t-> \tList all contacts")
  # print("\t\"numContacts\"\t->\tList number of contacts")
  print("\t\"send\" \t\t-> \tTransfer file to online contacts")
  print("\t\"receive\" \t-> \tGo online to receive a file from a contact")
  print("\t\"exit/quit\"\t-> \tExit SecureDrop\n")



def addContact(hash):
  # need to check if contact already exists

  list_of_contacts, list_of_emails = get_arr_contacts_helper(hash)

  fernet = Fernet(encryption.calculateKey(hash)[0])
  tempName = input("\tEnter Full Name: ").lower()
  while tempName in list_of_contacts:
    print("Duplicate Name! Sorry you already have", tempName, "with email", list_of_emails[list_of_contacts.index(tempName)],"saved as a contact")
    tempName = input("\tEnter Full Name or q to quit: ").lower()
  
  if tempName == 'q':
    print("Name iggnored ... returning back to SecureDrop")
    return

  tempEmail = input("\tEnter Email Address: ").lower()
  while tempEmail in list_of_emails:
    print("Duplicate Email! Sorry you already have", list_of_contacts[list_of_emails.index(tempEmail)], "with email", tempEmail,"saved as a contact")
    tempEmail = input("\tEnter Email Address or q to esc: ").lower()

  if tempEmail == 'q':
    print("Name and email iggnored ... returning back to SecureDrop")
    return
  addContactHelper(fernet, tempName, tempEmail)




def addContactHelper(fernet, tempName, tempEmail):
  FileCredibility.fullStop("contacts.txt")
  with open("contacts.txt", "a") as f:
    f.write(fernet.encrypt(tempName.encode()).decode() + "\n")
    f.write(fernet.encrypt(tempEmail.encode()).decode() + "\n")
    #f.write("\n") this line makes python think the file ends here, no idea why but yeah
  #sleep(0.1)
  FileCredibility.updateFiles(["contacts.txt"])
  
  print("Contact Added.\n")
  return



def removeContact(hash):
  contactFile = "contacts.txt"
  if not exists(contactFile) or os.stat(contactFile).st_size == 0:
    print("No contacts found. To add a contact write 'add'")
    return
    
  fullName = input("\tEnter full name of contact you wish to remove: ")
  removeContactHelper(hash, fullName, contactFile)
  return

  

def removeContactHelper(hash, fullName, contactFile):
  try:
    FileCredibility.fullStop(contactFile)
    with open(contactFile, "r") as f:
      lines = f.readlines()
  except:
    print("No contacts found. To add a contact write 'add'")
    return
    
  fernet = Fernet(encryption.calculateKey(hash)[0])

  with open(contactFile, "w") as f:
    bFound = False
    bMarker = False
    for line in lines:
      trueTerm = fernet.decrypt(line[:-1].encode()).decode()
      if (trueTerm != fullName and bFound == False):
        f.write(line)
      else:
        bMarker = True
        if(bFound == True):
          bFound = False
        else:
          bFound = True
    FileCredibility.updateFiles([contactFile])

  if(bMarker):
    print("Successfully removed contact " + fullName + ".\n")
  else:
    print("Cannot find \""+fullName+"\" in contact list.\n")

  return



def listContacts(hash):
  try:
    FileCredibility.fullStop("contacts.txt")
    contactFile = open("contacts.txt","r");
  except:
    print("No contacts found. To add a contact write 'add'")
    return

  counter = 0
  fernet = Fernet(encryption.calculateKey(hash)[0])
  line = contactFile.readline()[:-1]
  if(not line):
    print("No contacts found. To add a contact write 'add'")
  while (line):
    counter = counter + 1
    print("\tContact " + str(counter))
    print("\tName:\t"+fernet.decrypt(line.encode()).decode())
    line = contactFile.readline()[:-1]
    print("\tEmail:\t"+fernet.decrypt(line.encode()).decode())
    line = contactFile.readline()[:-1]
    if(line):
      print()

  contactFile.close()

  print()


def getNumUsers() -> int:
  if os.path.exists('userData.encrypted'):
    return 1
  return 0



def formatNumUsers() -> str:
  if not keysExist():
    leave(True)
    Error100(getframeinfo(currentframe()))
    quit()

  numU = getNumUsers()
  if numU == 1 :
    return "There is 1 user registerd.\n"

  return "There are " + str(numU) + " users registerd.\n"



def login_request():
  inp = input(formatNumUsers() + "Would you like to login or quit? ")
  while True:
    string = inp.lower().replace(" ", "")
    log_request = ['login', 'log', 'l', 'in']
    quit_request = ['q', 'e', 'quit', 'exit', 'leave', 'disconnect']

    if string in log_request:
      check_keys_error()
      return 0
    
    if string in quit_request:
      img.bye()
      leave(False)
    
    print("Could not understand '" + inp + "'")
    inp = input("Would you like to login or quit? ")
  
  return -1



def get_arr_contacts_helper(hash) -> ([str], [str]):
  masterArrName = []
  masterArrEmail = []

  try:
    FileCredibility.fullStop("contacts.txt")
    contactFile = open("contacts.txt","r");
  except:
    return (masterArrName, masterArrEmail)

  fernet = Fernet(encryption.calculateKey(hash)[0])
  line = contactFile.readline()[:-1]
  if(not line):
    return (masterArrName, masterArrEmail)
  
  while (line):
    name = fernet.decrypt(line.encode()).decode()
    line = contactFile.readline()[:-1]
    email = fernet.decrypt(line.encode()).decode()

    masterArrName.append(name)
    masterArrEmail.append(email)

    line = contactFile.readline()[:-1]
  
  contactFile.close()
  return (masterArrName, masterArrEmail)
  


def composite(userin, hash) -> bool:
  try:
    args = userin.replace('  ',' ').split(' ')
    if len(args) < 2:
      return False

    if args[0] == "add" and len(args) < 4:
      name, email = args[1], args[2]
      list_of_contacts, list_of_emails = get_arr_contacts_helper(hash)
      if name in list_of_contacts:
        print("Duplicate Name! Sorry you already have", name, "with email", list_of_emails[list_of_contacts.index(name)],"saved as a contact")
        addContact(hash)
        return True
      if email in list_of_emails:
        print("Duplicate Email! Sorry you already have", list_of_contacts[list_of_emails.index(email)], "with email", email,"saved as a contact")
        addContact(hash)
        return True
      addContactHelper(Fernet(encryption.calculateKey(hash)[0]), name, email)
      return True

    if args[0] == "remove":
      contactFile = "contacts.txt"
      if not exists(contactFile) or os.stat(contactFile).st_size == 0:
        print("No contacts found. To add a contact write 'add'")
        return False
        
      counter = 1
      print('')
      while counter < len(args):
        removeContactHelper(hash, args[counter], contactFile)
        counter += 1
      return True
  except:
    return False

  return False


def isCustomReceive(userin, hash, usr_email) -> bool:
  try:
    args = userin.lower().replace('  ', ' ').split(' ')
    if len(args) == 2 and type(int(args[1])) == int:
      receiver.receiveFile(hash, usr_email, TimeOut=int(args[1]))
      return True
  except:
    return False



def secureDrop():
  hash, usr_name, usr_email = login()

  print ("\nWelcome to SecureDrop.")
  print ('Type "help" for a list of commands.\n')

  while True:
    userInput = input("secure_drop> ")
    userinput = userInput.lower()
    
    if userinput == "help":
      helpCommands()

    elif userinput == "add":
      addContact(hash)

    elif(userinput == "remove"):
      removeContact(hash)

    elif(("remove" in userinput and composite(userinput, hash)) or ("add" in userinput and composite(userinput, hash))):
      continue
      
    elif(userinput == "list"):
      listContacts(hash)

    elif(userinput == "send"):
      sender.sendFile(hash, usr_email)

    elif(userinput == "receive"):
      receiver.receiveFile(hash, usr_email)

    elif "receive" in userinput and isCustomReceive(userinput, hash, usr_email):
      continue

    elif(userinput == "exit" or userinput == 'quit' or userinput == 'q'):
      img.bye()
      leave(False)
    
    elif userinput == 'self' or userinput == 'print' or userinput.replace(' ','') == 'whoami':
      print(f'I am ({usr_name=}, {usr_email=})')
    else:
      print(f"'{userInput}' is an invalid input.")

    # end of loop
  return




def keysExist() -> bool:
  if not exists('userData.encrypted') or os.stat('userData.encrypted').st_size == 0:
    return False

  return True



def Error100(address_at_error):
  print("Something went wrong in secure Drop on line", address_at_error.lineno, ".\nError code 100: User File empty, missing, or corrupted.")



def leave(isError):
  os.system('cls' if os.name == 'nt' else 'clear')
  if not isError:
    quit()







def main():
  init() 
  login_request()
  secureDrop()


if __name__ == '__main__':
  main()
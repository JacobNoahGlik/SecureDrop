# socket code from: https://github.com/nikhilroxtomar/File-Transfer-using-TCP-Socket-in-Python3/blob/main/client.py

import socket
import encryption
import EncMsg
import os
from cryptography.fernet import Fernet
import FileCredibility
import cryptography.exceptions
#import certificate_authority

EXIT_ARR = ['q','quit','exit','leave','dissconect', 'returntomenu', 'returntosecuredrop']

MAX_RECEIVE_SIZE = 1048575 # 1,048,575

def wishToLeave(filename):
  if filename.lower().replace(' ', '') in EXIT_ARR:
    ch = input(f'You entered {filename}, do you want to leave \'send\' and return to main menu in Secure Drop?(y/n)').lower()
    while ch != 'y' and ch != 'n':
      ch = input(f'You entered {filename}, do you want to leave \'send\' and return to main menu in Secure Drop?(y/n)').lower()
    return ch == 'y'


def getFileSize(file_name):
  return int(os.path.getsize(file_name)) + 1

  
def predictFileSize(file_name):
  return int(os.path.getsize(file_name) * 1.33) + 1



def sendFile(hash, usr_email):
  # server info
  IP = socket.gethostbyname(socket.gethostname())
  PORT = 4455
  ADDR = (IP, PORT)
  FORMAT = "utf-8"
  SIZE = 1024

  # see if there are any contacts
  try:
    FileCredibility.fullStop("contacts.txt")
    with open("contacts.txt", "r") as f:
      contactData = f.readlines()
  except:
    print("No contacts found. Sending a file requires having at least one contact. To add a contact type 'add'\n")
    return

  # create a TCP socket
  client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  try:
    # connect to the server
    client.connect(ADDR)
  except:
    print("There are no contacts online. Returning to SecureDrop menu.\n")
    client.close()
    return

  # send my info to the contact
  client.send(usr_email.encode(FORMAT))

  try:
    # get contacts that are online
    onlineContact = client.recv(SIZE).decode(FORMAT)
  except:
    print("\nLost connection to server. Returning to SecureDrop menu.\n")
    client.close()
    return

  # check if online contact is in contact list
  fernet = Fernet(encryption.calculateKey(hash)[0])
  contactFound = False
  marker = False
  for line in contactData:
    if (fernet.decrypt(line[:-1].encode()).decode() == onlineContact) and marker:
      contactFound = True
      break
    else:
      marker = True

  # if not in contacts return
  if (contactFound == False):
    print("Someone who is not in your contacts is trying to receive your file. Returning to SecureDrop menu.\n")
    client.close()
    return

  print("The following contacts are online:\n  * " + onlineContact)

  contact = input("\nPlease enter the email of the contact you wish to send a file to>> ")

  # check if contact is in contact list
  fernet = Fernet(encryption.calculateKey(hash)[0])
  contactFound = False
  marker = False
  for line in contactData:
    if (fernet.decrypt(line[:-1].encode()).decode() == contact) and marker:
      contactFound = True
      break
    else:
      marker = True

  # if not in contacts return
  if (contactFound == False):
    print("Contact not found in contacts list. Returning to SecureDrop menu.\n")
    client.close()
    return

  # check if contact entered is actually online
  if(onlineContact != contact):
    print("That contact is not online. Returning to SecureDrop menu.\n")
    client.close()
    return

  filename = input("Please enter the name of the file you wish to send>> ")
  if wishToLeave(filename):
    client.close()
    return

  while not os.path.exists(filename):
    print("Cannot find file '" + filename + "'.\n")
    print('You may enter \'quit\' or \'exit\' to leave this prompt.')
    filename = input("Please re-enter the name of the file you wish to send>> ")
    if wishToLeave(filename):
      client.close()
      return
  
  FileCredibility.updateFiles([filename])

  client.send("ready".encode(FORMAT))
  print("\nWaiting for contact to accept file transfer...")

  try:
    # receive message from server about accepted transfer request
    msg = client.recv(SIZE).decode(FORMAT)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return

  # if message doesnt actually come from the contact you tried sending to
  if contact not in msg:
    print("The response was not from your contact. Returning to SecureDrop menu.\n")
    client.close()
    return

  print(msg)

  # return to main if contact declines the file
  if "declined" in msg:
    print("Returning to SecureDrop menu.\n")
    client.close()
    return

  try:
    # receive the key file name and data
    keyFilename = client.recv(SIZE).decode(FORMAT)
    keyData = client.recv(SIZE).decode(FORMAT)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return

  # save key data
  with open(keyFilename, "w") as keyFile:
    keyFile.write(keyData)
  FileCredibility.updateFiles([keyFilename])

  # print("\nReceiver public key file has been received.")

  # let contact know that key file has been received
  client.send("Receiver public key file has been successfully transferred.".encode(FORMAT))

  try:
    # receive signature file name and data
    sigFilename = client.recv(SIZE).decode(FORMAT)
    sigData = client.recv(SIZE)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return

  # save signature data
  with open(sigFilename, "wb") as sigFile:
    sigFile.write(sigData)
  FileCredibility.updateFiles([sigFilename])

  # system auto authenticates

  # let client know that the authentication was successful
  client.send("Receiver signature file has been transferred and authenticated.".encode(FORMAT))

  # predict file size:
  predicted_size = predictFileSize(filename)
  client.send(f'size={predicted_size}'.encode(FORMAT))
  large_file = False
  if predicted_size > MAX_RECEIVE_SIZE:
    large_file = True
    print("\nThe file you are encrypting is large. This may take a moment...", end='\r')

  # generate sender public key file and encrypt the message filename
  fn = filename.split('.')[0]
  extension = '.' + filename.split('.')[1]
  try:
    sym_key = EncMsg.gen_sender_key_file()
  except cryptography.exceptions.InvalidSignature:
    print('\nr.pub is a forgery! The receiver is not who they say they are!')
    print("Returning to SecureDrop menu.\n")
    client.close()
    return

  if type(sym_key) == int and sym_key == -1:
    print("\ncertificate authority declined to sign public key file")
    print("Returning to SecureDrop menu.\n")
    client.close()
    return
  if EncMsg.gen_send_file(sym_key, fn, extension):
    if large_file:
      print("The file you are encrypting is large. This may take a moment... Success!")
  else:
    print("Failed to encrypt the file. ERROR_26: file too large")

  # send the sender public key filename
  client.send("s.pub".encode(FORMAT))

  # get key data
  FileCredibility.fullStop("s.pub")
  with open("s.pub", "rb") as sender_public_key_file:
    sender_public_key_data = sender_public_key_file.read()
    
  # send the sender public key data
  client.send(sender_public_key_data)

  try:
    # receive message about successfull public key file transfer
    msg = client.recv(SIZE).decode(FORMAT)
    # print(msg)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return

  # send the sender signature filename
  client.send("s.sig".encode(FORMAT))

  # get signature file data
  FileCredibility.fullStop("s.sig")
  with open("s.sig", "rb") as sender_sig_file:
    sender_sig_data = sender_sig_file.read()

  # send sig file data
  client.send(sender_sig_data)

  try:
    # receive message about successful transfer of sig file
    msg = client.recv(SIZE).decode(FORMAT)
    # print(msg)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return

  # send enc-message filename to server
  client.send(filename.encode(FORMAT))

  # send enc-message file size to server
  filesize = getFileSize(filename.split('.')[0] + '.zok')
  client.send(f'size={filesize}'.encode(FORMAT))

  # get encrypted message data
  fenc = filename.split(".")[0] + ".zok"
  FileCredibility.fullStop(fenc)
  file = open(fenc, "rb")
  data = file.read()
  file.close()
  
  try:
    decision = client.recv(SIZE).decode(FORMAT)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return
  if decision == 'n':
    print("\n" + contact + " has declined the large file. Returning to SecureDrop menu.\n")
    client.close()
    return
  
  print(f'\n{filename} sending...',end='\r')
  # send encrypted message data 
  client.sendall(data)

  # receive message from server about successful file transfer
  try:
    msg = client.recv(SIZE).decode(FORMAT)
    if ' has been successfully transferred.' in msg:
      print(f'{filename} has been successfully transferred!\n')
    else:
      print("\n" + msg + "\n")
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    client.close()
    return

  # end connection from server
  client.close()

  return
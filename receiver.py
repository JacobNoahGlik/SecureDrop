# socket code from: https://github.com/nikhilroxtomar/File-Transfer-using-TCP-Socket-in-Python3/blob/main/client.py

import socket
import EncMsg
import encryption
import os
from cryptography.fernet import Fernet
import FileCredibility
#import certificate_authority
import cryptography.exceptions
import pathlib
MAX_RECEIVE_SIZE = 1048575
import time

transfer_time = 10

def bigfile_andusercontinue(filesize) -> bool:
  dif = 0.9425
  transfer_time = (filesize * dif / 10000000)
  print(f'\nWARNING:\n\tThe sender is trying to send a file larger then one megabyte.\n (encrypted_size = {(filesize * dif / 1000000):.2f} mb) This file transfer may take up to {transfer_time:.2f} seconds to complete!')
  ch = input('\tDo you have the space / would you like to receive this file(y/n) ').lower().replace(' ', '')
  while ch != 'n' and ch != 'y':
    print(f'\nWARNING:\n\tThe sender is trying to send a file larger then one megabyte.\n (encrypted_size = {(filesize * dif / 1000000):.2f} mb) This file transfer may take up to {transfer_time:.2f} seconds to complete!')
    ch = input('\tDo you have the space / would you like to receive this file(y/n) ').lower().replace(' ', '')
  
  return (ch == 'y')



def extrapolateFileSize(size_string):
  if not 'size=' in size_string:
    print('something went wrong while getting senders file size')
  try:
    return int(size_string.replace('size=',''))
  except:
    print(f'something went wrong while getting senders file size. debug:{size_string}')



def receiveFile(hash, usr_email, TimeOut=30):
  # server info
  IP = socket.gethostbyname(socket.gethostname())
  PORT = 4455
  ADDR = (IP, PORT)
  SIZE = 2048
  FORMAT = "utf-8"

  # see if there are any contacts. return if none
  try:
    FileCredibility.fullStop("contacts.txt")
    with open("contacts.txt", "r") as f:
      contactData = f.readlines()
  except:
    print("No contacts found. Receiving a file requires having at least one contact. To add a contact type 'add'\n")
    return

  # create a TCP socket
  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  try:
    # connect to the server
    server.bind(ADDR)
  except:
    print("Someone is already using the server. Try again later.\nReturning to SecureDrop menu.\n")
    return

  print(f"Server is listening for file transfer requests... \n(if no file transfer requests come in {TimeOut} seconds, your connection will be timed out)")
  if TimeOut == 30:
    print('Timeout is set to 30 sec by default, change this by typing \'receive <int:time>\' for a custom timeout time.')
  
  time_alloc = 0.2
  connected = False
  server.settimeout(time_alloc)
  print(f'Returning to main menu in: {TimeOut:.1f} seconds', end='\r')
  while TimeOut >= 0:
    try:
      # turn on listener
      TimeOut -= time_alloc
      server.listen()
      # incoming request to transfer file
      conn, addr = server.accept()
      print('\n')
      connected = True
      break
    except socket.timeout:
      if TimeOut >= 0:
        print(f'Returning to main menu in: {TimeOut:.1f} seconds', end='\r')


  if not connected:
    print("\nServer timed out. \nReturning to SecureDrop menu.\n")
    return
  

  try:
    # receive name of contact that is sending the file
    contact = conn.recv(SIZE).decode(FORMAT)
  except:
    print("\nLost connection to server. Returning to SecureDrop menu.\n")
    conn.close()
    return

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
    print("Someone who is not in your contacts list is trying to send you a file. Declining request and returning to SecureDrop menu.\n")
    conn.close()
    return

  # send my info to show that I am online
  conn.send(usr_email.encode(FORMAT))

  try:
    # when contact is ready
    ready = conn.recv(SIZE).decode(FORMAT)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  if(ready != "ready"):
    print("The sender has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  # ask if receiver wants to accept the file transfer
  c = input("\nContact '" + contact + "' is sending a file. Accept (y/n)? ")
  while 'n' != c != 'y':
    print("Invalid input.")
    c = input("Contact '" + contact + "' is sending a file. Accept (y/n)? ")


  # let contact know about your choice
  if(c == 'n'):
    conn.send(("Contact '" + usr_email + "' has declined the transfer request.").encode(FORMAT))
    conn.close()
    print()
    return
  else:
    conn.send(("Contact '" + usr_email + "' has accepted the transfer request.").encode(FORMAT))


  # generate key and signature file
  one_time_receiver_private_key = EncMsg.gen_receiver_key_file()

  if type(one_time_receiver_private_key) == int and one_time_receiver_private_key == -1:
    print("certificate authority declined to sign public key file")
    print("Returning to SecureDrop menu.\n")
    conn.close()
    return

  # send receiver public key file name
  conn.send("r.pub".encode(FORMAT))

  # get public key data
  FileCredibility.fullStop("r.pub")
  with open("r.pub", "r") as keyFile:
    keyData = keyFile.read()

  # send receiver public key file data
  conn.send(keyData.encode(FORMAT))

  try:
    # receive message that key file transfer was successful
    msg = conn.recv(SIZE).decode(FORMAT)
    # print("\n" + msg)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  # send signature file name
  conn.send("r.sig".encode(FORMAT))

  # get signature file data
  FileCredibility.fullStop("r.sig")
  with open("r.sig", "r") as sigFile:
    sigData = sigFile.read()

  # send signature file data
  conn.send(sigData.encode(FORMAT))

  try:
    # message about signature file successful authentication
    msg = conn.recv(SIZE).decode(FORMAT)
    # print(msg)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  try:
    predicted_size = extrapolateFileSize(conn.recv(SIZE).decode(FORMAT))
    if(predicted_size >= MAX_RECEIVE_SIZE):
      print(contact + " is encrypting a large file. This may take a moment...")
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  try:
    # receive sender public key filename and data
    sender_public_key_filename = conn.recv(SIZE).decode(FORMAT)
    sender_public_key_data = conn.recv(SIZE).decode(FORMAT)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  # save sender public key data
  FileCredibility.fullStop(sender_public_key_filename)
  with open(sender_public_key_filename, "w") as sender_public_key_file:
    sender_public_key_file.write(sender_public_key_data)
  FileCredibility.updateFiles([sender_public_key_filename])

  # print("Sender public key file has been received.")

  # let sender know we have received the senders public key file
  conn.send("Sender public key file has been successfully transferred.".encode(FORMAT))

  try:
    # receive sig filename and data
    sender_sig_filename = conn.recv(SIZE).decode(FORMAT)
    sender_sig_data = conn.recv(SIZE)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  # save sig file data
  FileCredibility.fullStop(sender_sig_filename)
  with open(sender_sig_filename, "wb") as sender_sig_file:
    sender_sig_file.write(sender_sig_data)
  
  FileCredibility.updateFiles([sender_sig_filename])

  # print("Sender signature file has been received and authenticated")
  conn.send("Sender signature file has been transferred and authenticated.".encode(FORMAT))

  try:
    # receive message filename
    filename = conn.recv(SIZE).decode(FORMAT)
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return
  
  # create directory for received files if it doesnt exist already
  if not pathlib.Path('receivedFiles').is_dir():
    os.mkdir('receivedFiles', 0o777)
  filename = "receivedFiles/" + filename

  try:
    # receive file size
    filesize = extrapolateFileSize(conn.recv(SIZE).decode(FORMAT))
  except:
    print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
    conn.close()
    return

  if type(filesize) != int:
    print('File size was not understood')
    print("Returning to SecureDrop menu.\n")
    conn.close()
    return

  # if bigger then max receive size
  big_file = False
  if filesize > MAX_RECEIVE_SIZE:
    if bigfile_andusercontinue(filesize):
      conn.send("y".encode(FORMAT))
      print('\nReceiving very large file...',end='\r')
      time.sleep(0.1)
      big_file = True
      # custom situation
      max_iterations = filesize // MAX_RECEIVE_SIZE
      with open(filename, "wb") as file:
        for iteration in range(max_iterations):
          try:
            filedata = conn.recv(MAX_RECEIVE_SIZE)
          except:
            print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
            conn.close()
            return
          file.write(filedata)
          try:
            print(f'Receiving very large file: package {iteration} of {max_iterations + 1}',end='\r')
          except:
            print(f'print_failed',end='\r')
        try:
          filedata = conn.recv(filesize % MAX_RECEIVE_SIZE + 10)
        except:
          print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
          conn.close()
          return
        file.write(filedata)
        print(f'Receiving very large file: package {max_iterations + 1} of {max_iterations + 1}.')
    else:
      conn.send("n".encode(FORMAT))
      print(f'\nDeclining {contact}\'s file.')
      print("Returning to SecureDrop menu.\n")
      conn.close()
      return
  else:# if not bigger then max receive size
    # default situation
    conn.send("not_too_big".encode(FORMAT))
    with open(filename, "wb") as file:
      try:
        filedata = conn.recv(filesize)
      except:
        print("\n" + contact + " has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return
      file.write(filedata)

  # save data
  #with open(filename, "wb") as file:
  #  file.write(data)
  FileCredibility.updateFiles([filename])
  fnout = filename.split('/')[1]
  print("\n" + fnout + " has been received.\n")

  # decrypt message file
  fn = filename.split('.')[0]
  extension = '.' + filename.split('.')[1]
  if big_file:
    size = int(os.path.getsize(filename)) + 1
    calc_mb = (size * 0.0009765625 / 1000)
    print(f'Beginning to decrypt {fnout} ({calc_mb:.2f} mb), aprox: {(calc_mb * 0.0936037441 / 10):.1f} seconds')

  try:
    if(EncMsg.decrypt_incoming_file(fn, extension, one_time_receiver_private_key)):
      print(fnout + " has been decrypted.\n")
    else:
      print(fnout + " failed the decryption process.\n")
  except cryptography.exceptions.InvalidSignature:
    print('s.pub is a forgery!')
    print("Returning to SecureDrop menu.\n")
    conn.close()
    return
  
  # let contact know that file has been received
  conn.send((fnout + " has been successfully transferred.").encode(FORMAT))

  # end connection from server
  conn.close()
  return
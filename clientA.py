#! /usr/bin/env python3.8
import socket
from socket import *
import hashlib
import base64
from cryptography.fernet import Fernet
import sys
import threading
import os
import signal 

serverName = 'hostname'
serverIP = "127.0.0.1"
serverPort = 12000
clientID = 'clientA'
key = 'a3c52bc7fd3a125e'
clientSocket = socket(AF_INET, SOCK_DGRAM)

def receive(): 
    while True:
        try:
            msg = clientSocket.recv(1024).decode()
            print(msg)
        except:
            clientSocket.close()
            sys.exit()
            break

def write():
    while True:
        chat = input('')
        msgChat = '{}: {}'.format(clientID, chat)
        clientSocket.send(msgChat.encode())
        if chat == "Log off":
            #logoffMsg = clientSocket.recv(1024)
            #print(logoffMsg)
            print("Disconnecting")
            clientSocket.close()
            sys.exit()
            break
  
clientSocket.sendto(clientID.encode(), (serverIP, serverPort))

randrecv, serverAddress = clientSocket.recvfrom(2048)
randcheck = randrecv.decode()
#print(randcheck)

hashSolve = str(randcheck)+key
h = hashlib.new('sha256')
h2 = hashlib.new('md5')
hashFunc = hashSolve.encode()
h.update(hashFunc)
h2.update(hashFunc)
ck_a = h2.hexdigest()

clientSocket.sendto(h.hexdigest().encode(), serverAddress)

authMsg, serverAddress = clientSocket.recvfrom(1024)
if authMsg.decode() == 'Client not found. Aborting':
    print(authMsg.decode())
    clientSocket.close()
    sys.exit() 

cipher_suite = Fernet(base64.urlsafe_b64encode(bytes(ck_a, 'utf-8')))
authDec = cipher_suite.decrypt(authMsg).decode()
#print(authDec)

splitByComma = authDec.split(',')
randCookie = splitByComma[0]
serverTcp = splitByComma[1]
#print(randCookie)
print(serverTcp)

clientSocket.close()

#initiating tcp connection
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverIP, int(serverTcp)))
clientSocket.send(randCookie.encode())
connected = clientSocket.recv(1024)

print(connected.decode())
#while True:
#    chat = input(">")
#    clientSocket.send(chat.encode())

#    if chat == "Log off":
        #logoffMsg = clientSocket.recv(1024)
        #print(logoffMsg)
#        print("Disconnecting")
#        clientSocket.close()
#        sys.exit()

#        msg = clientSocket.recv(1024).decode()
#        print(msg)


receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()


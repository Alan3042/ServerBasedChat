#! /usr/bin/env python3.8
import socket
from socket import *
import hashlib
import base64
from cryptography.fernet import Fernet

serverName = 'hostname'
serverIP = "127.0.0.1"
serverPort = 12000
clientID = 'client1'
key = 'a3c52bc7fd3a125e'
clientSocket = socket(AF_INET, SOCK_DGRAM)
clientSocket.sendto(clientID.encode(), (serverIP, serverPort))

randrecv, serverAddress = clientSocket.recvfrom(2048)
randcheck = randrecv.decode()
print(randcheck)

hashSolve = str(randcheck)+key
h = hashlib.new('sha256')
h2 = hashlib.new('md5')
hashFunc = hashSolve.encode()
h.update(hashFunc)
h2.update(hashFunc)
ck_a = h2.hexdigest()

clientSocket.sendto(h.hexdigest().encode(), serverAddress)

authMsg, serverAddress = clientSocket.recvfrom(2048)
cipher_suite = Fernet(base64.urlsafe_b64encode(bytes(ck_a, 'utf-8')))
authDec = cipher_suite.decrypt(authMsg)
print(authDec.decode())

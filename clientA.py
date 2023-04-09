#! /usr/bin/env python3
import socket
from socket import *
import hashlib

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
hashFunc = hashSolve.encode()
h.update(hashFunc)
clientSocket.sendto(h.hexdigest().encode(), (serverIP, serverPort))

authMsg, serverAddress = clientSocket.recvfrom(2048)


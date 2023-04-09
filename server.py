#! /usr/bin/env python3

import socket
from socket import *
import hashlib
import random
import secrets

serverPort = 12000
k_a = "a3c52bc7fd3a125e" 
k_b = "b0c2499ad74cf2a4"
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', serverPort))
print ("The server is ready to receive")
while True:
    clientID, clientAddress = serverSocket.recvfrom(2048)
    checkID = clientID.decode()

    print(checkID)
    #if checkID != k_a:
       # message = "Key does not match"
       # serverSocket.sendto(message.encode(), clientAddress)

    rand = random.randint(1,10)
    h = hashlib.new('sha256')
    hashString = str(rand)+k_a
    hashFunc = hashString.encode()
    h.update(hashFunc)
    xres = h.hexdigest()
    serverSocket.sendto(str(rand).encode(), clientAddress)

    chalAns, clientAddress = serverSocket.recvfrom(2048)
    res = chalAns.decode()
    
    print(res)
    print(xres)

    if res == xres: 
        print("SUCCESS")
        genKey = token_hex(16)
        

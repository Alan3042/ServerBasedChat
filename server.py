#! /usr/bin/env python3.8

import socket
from socket import *
import hashlib
import random
import base64
from cryptography.fernet import Fernet

#from nltk.tokenize import word_tokenize
#with open ('myfile.txt') as fin:
#    tokens = word_tokenize(fin.read())

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
    h2 = hashlib.new('md5')

    hashString = str(rand)+k_a
    hashFunc = hashString.encode()
    h.update(hashFunc)
    xres = h.hexdigest()

    h2.update(hashFunc)
    ck_a = h2.hexdigest()
    print("ck_a: " + ck_a)

    serverSocket.sendto(str(rand).encode(), clientAddress)

    chalAns, clientAddress = serverSocket.recvfrom(2048)
    res = chalAns.decode()

    print(res)
    print(xres)

    if res == xres: 
        print("SUCCESS")
        randCookie = random.randint(1,10)
        authSuccess = str(randCookie) + ',' + str(serverPort)
        print(authSuccess)

        #encrypt and send auth message
        b = base64.urlsafe_b64encode(bytes(ck_a, 'utf-8'))
        print(b)
        cipher_suite = Fernet(b)
        print("Encrypting")
        authEnc = cipher_suite.encrypt(authSuccess.encode())
        serverSocket.sendto(authEnc, clientAddress)

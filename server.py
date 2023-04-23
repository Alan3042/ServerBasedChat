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

udpAddress = "127.0.0.1"
tcpAddress = "127.0.0.1"
udpPort = 12000
tcpPort = 12000 

name, keys = 4, 2
keyArr = [[0 for i in range(keys)] for j in range(name)]
keyArr[0][0] = "clientA"
keyArr[0][1] = "a3c52bc7fd3a125e"
keyArr[1][0] = "clientB"
keyArr[1][1] = "b0c2499ad74cf2a4"

def column(keyArr, c):
    return [row[c] for row in keyArr]
#for name in keyArr:
#    print(name)

serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((udpAddress, udpPort))
print ("The server is ready to receive")
while True:
    clientID, clientAddress = serverSocket.recvfrom(1024)
    checkID = clientID.decode()
    print(checkID)
    index = 0
    idColumn = column(keyArr, 0)
    keyColumn = column(keyArr, 1)
    for i in idColumn:
        print("Checking name: " + str(i))
        if checkID == str(i):
            print(index)
            print(keyColumn[index])
            checkKey = keyColumn[index]
        index += 1
           #if checkID != j:
             #message = "Key does not match"
             #serverSocket.sendto(message.encode(), clientAddress)
             #serverSocket.close()
             #break

    print("Checking key: " + checkKey)
    rand = random.randint(1,10)
    h = hashlib.new('sha256')
    h2 = hashlib.new('md5')

    hashString = str(rand)+checkKey
    hashFunc = hashString.encode()
    h.update(hashFunc)
    xres = h.hexdigest()

    h2.update(hashFunc)
    ck_a = h2.hexdigest()
    #print("ck_a: " + ck_a)

    serverSocket.sendto(str(rand).encode(), clientAddress)

    chalAns, clientAddress = serverSocket.recvfrom(1024)
    res = chalAns.decode()

    #print(res)
    #print(xres)

    if res != xres: 
        msgFail = "Client not found. Aborting"
        serverSocket.sendto(msgFail.encode(), clientAddress)
        break

    #print("SUCCESS")
    randCookie = random.randint(1,10)
    authSuccess = str(randCookie) + ',' + str(tcpPort)
    #print(authSuccess)

    #encrypt and send auth message
    b = base64.urlsafe_b64encode(bytes(ck_a, 'utf-8'))
    #print(b)
    cipher_suite = Fernet(b)
    print("Encrypting")
    authEnc = cipher_suite.encrypt(authSuccess.encode())
    serverSocket.sendto(authEnc, clientAddress)
    serverSocket.close()

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind((tcpAddress, tcpPort))
    serverSocket.listen(1)
    connect, clientAddress = serverSocket.accept()
    print(f"Connected by {clientAddress}")
    while 1:
        data = connect.recv(1024)
        if not data: break
        print("recieved data:", data)
        
        connect.send(f"You are now connected to {tcpAddress}".encode())

        clientResponse = connect.recv(1024)

        if clientResponse.decode() == "Log off":
            print(f"{clientAddress} disconnected")

        #serverSocket.close()
 

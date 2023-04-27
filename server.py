#! /usr/bin/env python3.8

import socket
from socket import *
import hashlib
import random
import base64
from cryptography.fernet import Fernet
import threading

udpAddress = "127.0.0.1"
tcpAddress = "127.0.0.1"
udpPort = 12000
tcpPort = 5001 

name, keys = 4, 2
keyArr = [[0 for i in range(keys)] for j in range(name)]
keyArr[0][0] = "clientA"
keyArr[0][1] = "a3c52bc7fd3a125e"
keyArr[1][0] = "clientB"
keyArr[1][1] = "b0c2499ad74cf2a4"
keyArr[2][0] = "clientC"
keyArr[2][1] = "c341ad84cbf67fea" 
keyArr[3][0] = "clientD"
keyArr[3][1] = "d875acd920bfe21c"

threads = []

def column(keyArr, c):
    return [row[c] for row in keyArr]
#for name in keyArr:
#    print(name)

def broadcast(msg):
    for user in threads:
        user.send(msg)
def threadTCP(c):
    print(threads)
    while True:
        try:
            data = c.recv(1024)

            broadcast(data)
        except:
            threads.remove(c)
            c.close()
            print(f"{clientAddress} disconnected")
            break

def tcpConn():
    while True:
        connect, clientAddress = serverTCP.accept()
        print(f"Connected by {clientAddress}")
        
        connect.send(f"You are now connected to {tcpAddress}".encode())

        thread = threading.Thread(target=threadTCP, args=(connect,))
        thread.start()

        #clientResponse = connect.recv(1024)

        #if clientResponse.decode() == "Log off":
        #    print(f"{clientAddress} disconnected")


        
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((udpAddress, udpPort))

serverTCP = socket(AF_INET, SOCK_STREAM)
serverTCP.bind((tcpAddress, tcpPort))
serverTCP.listen(4)

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

    print("Client authenticated")
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

    connect, clientAddress = serverTCP.accept()
    print(f"Connected by {clientAddress}")

    connect.send(f"You are now connected to {tcpAddress}".encode())

    threads.append(connect)

    thread = threading.Thread(target=threadTCP, args=(connect,))
    thread.start()
    #tcpConn()     

serverSocket.close()
 

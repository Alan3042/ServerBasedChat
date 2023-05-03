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

connUser = []
threads = []
chatRoom1 = []
chatRoom1User = []
chatRoom2 = []
chatRoom2User = []

def column(arr, c):
    return [row[c] for row in arr]
	#for name in keyArr:
	#print(name)

def udpServer():
    global keyArr
    serverPort = udpPort
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind((udpAddress, int(serverPort)))
    print("The server is ready to receive")

    while True:
        rand = random.randint(0, 100)
        message, clientAddress = serverSocket.recvfrom(1024)
        print(f"Received message '{message.decode()}' from {clientAddress}")
        clientID, msg = message.decode().split(":")
        keyIndex = [i for i, row in enumerate(keyArr) if row[0] == clientID][0]
        secretKey = keyArr[keyIndex][1].encode()
        h = hashlib.sha256(secretKey)
        key = h.digest()
        f = Fernet(base64.urlsafe_b64encode(key))
        decryptedMessage = f.decrypt(msg.encode()).decode()
        print(f"Decrypted message '{decryptedMessage}'")
        modifiedMessage = decryptedMessage.upper()
        encryptedMessage = f.encrypt(modifiedMessage.encode())
        print(f"Sending message '{encryptedMessage.decode()}' to {clientAddress}")
        serverSocket.sendto(encryptedMessage, clientAddress)

def end_chat(chat_room_users, chat_room):
    for user in chat_room_users:
        user.send("Ending session".encode())
    del chat_room_users[:]
    del chat_room[:]
    print("Chat ended")

def userChat1(c1):
    while True:
        msg = c1.recv(1024)
        print(msg.decode())
        cmdSplit = msg.decode().split(': ')
        cmd = cmdSplit[1]
        print(cmd)
        if cmd == "End chat":
            #for user in chatRoom1User:
            #    user.send("Ending session".encode())
            #del chatRoom1User[:]
            #del chatRoom1[:]
            #print("Chat ended")
            end_chat(chatRoom1User, chatRoom1)
            break
        if cmd == "History":
            f = open("chatroom1.txt", "r")
            c1.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        else:
            f = open("chatroom1.txt", "a") #append to chat instead of overwriting
            f.write(msg.decode() + "\n")
            f.close()
            for user in chatRoom1User:
                if user != c1:
                    user.send(msg)

def userChat2(c2):
    while True:
        msg = c2.recv(1024)
        print(msg.decode())
        cmdSplit = msg.decode().split(': ')
        cmd = cmdSplit[1]
        if cmd == "End chat":
            #for user in chatRoom1User:
            #    user.send("Ending session".encode())
            #del chatRoom2User[:]
            #del chatRoom2[:]
            #print("Chat ended")
            end_chat(chatRoom2User, chatRoom2)
            break
        if cmd == "History":
            f = open("chatroom2.txt", "r")
            c2.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        else:
            f = open("chatroom2.txt", "a") #append to chat instead of overwriting
            f.write(msg.decode() + "\n")
            f.close()
            for user in chatRoom2User:
                if user != c2:
                    user.send(msg)

def threadTCP(c, clientAddress):
    while True:
        data = c.recv(1024)
        decoded_data = data.decode().strip()
        print('Waiting for a connection...')

        # Logging off
        if decoded_data == "Log off":
            threads.remove(c)  # Remove from thread array before closing connection
            c.close()
            print(f"{clientAddress} disconnected")
            break

        # Chat
        elif decoded_data.startswith("Chat"):
            checkName = decoded_data[5:]
            if checkName in connUser:
                userIndex = connUser.index(checkName)
                toChat = threads[userIndex]
                in_session = False

                # Checking if the requested user is already in another session
                for user_list in [chatRoom1User, chatRoom2User]:
                    if toChat in user_list:
                        c.send(f"{checkName} is already in a session".encode())
                        in_session = True
                        break

                if not in_session:
                    # Will add to chat room if it is empty
                    if not chatRoom1:
                        print("Starting chatroom 1")

                        # Users in chat room
                        chatRoom1User.append(c)
                        chatRoom1User.append(toChat)

                        for user in chatRoom1User:
                            chatThread1 = threading.Thread(target=userChat1, args=(user,))
                            chatThread1.start()

                            # Thread array for chatroom
                            chatRoom1.append(chatThread1)

                        c.send(f"Connected to {checkName}".encode())
                        toChat.send(f"Connected to {clientAddress}".encode())

                        for chat_thread in chatRoom1:
                            chat_thread.join()

                        print("Users connected")
                        break

                    elif not chatRoom2:
                        print("Starting chatroom 2")

                        chatRoom2User.append(c)
                        chatRoom2User.append(toChat)

                        for user in chatRoom2User:
                            chatThread2 = threading.Thread(target=userChat2, args=(user,))
                            chatThread2.start()

                            chatRoom2.append(chatThread2)

                        c.send(f"Connected to {checkName}".encode())
                        toChat.send(f"Connected to {clientAddress}".encode())

                        for chat_thread in chatRoom2:
                            chat_thread.join()

                        print("Users connected")
                        break

            else:
                c.send(f"{checkName} unreachable".encode())

serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((udpAddress, udpPort))

serverTCP = socket(AF_INET, SOCK_STREAM)
serverTCP.bind((tcpAddress, tcpPort))
serverTCP.listen(4)

print ("The server is ready to receive")
while True:
    clientID, clientAddress = serverSocket.recvfrom(1024)
    checkID = clientID.decode()
    #print(checkID)
    index = 0
    idColumn = column(keyArr, 0)
    keyColumn = column(keyArr, 1)
    for i in idColumn:
        #print("Checking name: " + str(i))
        if checkID == str(i):
            #print(index)
            #print(keyColumn[index])
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
        msgFail = "Client not found. Aborting !!"
        serverSocket.sendto(msgFail.encode(), clientAddress)
        break

    print("Client authenticated !!")
    randCookie = random.randint(1,10)
    authSuccess = str(randCookie) + ',' + str(tcpPort)      #auth success message
    #print(authSuccess)
    connUser.append(clientID.decode())
    #print(connUser)

    #encrypt and send auth message
    b = base64.urlsafe_b64encode(bytes(ck_a, 'utf-8'))  #64-byte urlsafe 
    #print(b)
    cipher_suite = Fernet(b)                            #Fernet encryption
    print("Encrypting now !!")
    authEnc = cipher_suite.encrypt(authSuccess.encode())
    serverSocket.sendto(authEnc, clientAddress)

    #Allow client to connect to server
    c, clientAddress = serverTCP.accept()
    print(f"Connected by {clientAddress}")

    c.send(f"You are now connected to {tcpAddress}".encode())

    threads.append(c)

    thread = threading.Thread(target=threadTCP, args=(c, clientAddress))
    thread.start()

serverSocket.close()
 

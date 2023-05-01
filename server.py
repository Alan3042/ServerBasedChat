#! /usr/bin/env python3.8

import socket
from socket import *
import hashlib
import random
import base64
from cryptography.fernet import Fernet
import threading

# set up the IP address and port number for UDP and TCP sockets
udpAddress = "127.0.0.1"
tcpAddress = "127.0.0.1"
udpPort = 12000
tcpPort = 5001 

# set up the keys for clients
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

# set up lists to keep track of connected users and chat rooms
connUser = []
threads = []
chatRoom1 = []
chatRoom2 = []

# helper function to extract a column from a 2D array
def column(arr, c):
    return [row[c] for row in arr]

# function to handle chat messages in chat room 1
def userChat1(c1):
    while True:
        # receive message from client
        msg = c1.recv(1024)
        print(msg.decode())
        
        # extract command from message
        cmdSplit = msg.decode().split(': ')
        cmd = cmdSplit[1]
        print(cmd)
        
        # if command is to end the chat session, notify all users in the chat room and break out of the loop
        if cmd == "End chat":
            for user in chatRoom1:
                user.send("Ending session".encode())
                chatRoom1.remove(user)
            print("Chat ended")
            break
        
        # if command is to show chat history, send history to current user
        if cmd == "History":
            f = open("chatroom1.txt", "r")
            c1.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        
        # otherwise, append message to chat history file and send message to all users in chat room
        else:
            f = open("chatroom1.txt", "a")
            f.write(msg.decode() + "\n")
            f.close()
            for user in chatRoom1:
               user.send(msg)

# function to handle chat messages in chat room 2
def userChat2(c2):
    while True:
        # receive message from client
        msg = c2.recv(1024)
        print(msg.decode())
        
        # extract command from message
        cmdSplit = msg.decode().split(': ')
        cmd = cmdSplit[1]
        
        # if command is to end the chat session, notify all users in the chat room and break out of the loop
        if cmd == "End chat":
            for user in chatRoom2:
                user.send("Ending session".encode())
                chatRoom2.remove(user)
            print("Chat ended")
            break
        
        # if command is to show chat history, send history to current user
        if cmd == "History":
            f = open("chatroom2.txt", "r")
            c2.send(("CHAT HISTORY\n" + f.read()).encode())
            f.close()
        else:
            f = open("chatroom2.txt", "a")
            f.write(msg.decode() + "\n")
            f.close()
            for user in chatRoom2:
                user.send(msg)

def threadTCP(c):
    while True:
        data = c.recv(1024)

        #Logging off
        if data.decode() == "Log off":
            threads.remove(c)               #Remove from thread array before closing connection
            c.close()
            print(f"{clientAddress} disconnected")
            break

        # Check if the user requested to chat with is already in another session
        for name in connUser:
            if name == data.decode():
                userIndex = connUser.index(data.decode())
                toChat = threads[userIndex]

                # Checking if the requested user is already in another session
                if chatRoom1:
                    inSession = False
                    for user in chatRoom1:
                        if user == toChat:
                            c.send((data.decode() + " is already in a session").encode())
                            inSession = True
                    if inSession == True:
                        break

                if chatRoom2:
                    inSession = False
                    for user in chatRoom2:
                        if user == toChat:
                            c.send((data.decode() + " is already in a session").encode())
                            inSession = True
                    if inSession == True:
                        break

                # Add to chat room if it is empty
                if not chatRoom1:
                    print("Starting chatroom 1")
                    chatRoom1.append(c)
                    chatRoom1.append(toChat)

                    # Start chat threads for all users in chatroom1
                    for user in chatRoom1:
                        chatThread1 = threading.Thread(target=userChat1, args=(user, ))
                        chatThread1.start()

                    # Send messages to clients indicating they have connected
                    c.send(f"Connected to {data.decode()}".encode())
                    toChat.send(f"Connected to {clientAddress}".encode())
                    print("Users connected")
                    break

                if not chatRoom2:
                    print("Starting chatroom 2")
                    chatRoom2.append(c)
                    chatRoom2.append(toChat)

                    # Start chat threads for all users in chatroom2
                    for user in chatRoom2:
                        chatThread2 = threading.Thread(target=userChat2, args=(user, ))
                        chatThread2.start()

                    # Send messages to clients indicating they have connected
                    c.send(f"Connected to {data.decode()}".encode())
                    toChat.send(f"Connected to {clientAddress}".encode())
                    print("Users connected")
                    break
        
# Create a UDP socket and bind it to the specified address and port
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((udpAddress, udpPort))

# Create a TCP socket and bind it to the specified address and port, and listen for incoming connections
serverTCP = socket(AF_INET, SOCK_STREAM)
serverTCP.bind((tcpAddress, tcpPort))
serverTCP.listen(4)

# Print message to indicate that the server is ready to receive requests
print ("The server is ready to receive")

# Loop infinitely to receive client requests
while True:
    
    # Receive client ID from the UDP socket
    clientID, clientAddress = serverSocket.recvfrom(1024)
    
    # Decode the client ID received and use it to check against the key array
    checkID = clientID.decode()
    index = 0
    idColumn = column(keyArr, 0)
    keyColumn = column(keyArr, 1)
    for i in idColumn:
        if checkID == str(i):
            checkKey = keyColumn[index]
        index += 1
    
    # Generate a random number and use the SHA256 hash function to calculate xres
    rand = random.randint(1,10)
    h = hashlib.new('sha256')
    hashString = str(rand)+checkKey
    hashFunc = hashString.encode()
    h.update(hashFunc)
    xres = h.hexdigest()

    # Use the MD5 hash function to calculate ck_a
    h2 = hashlib.new('md5')
    h2.update(hashFunc)
    ck_a = h2.hexdigest()

    # Send the random number to the client over the UDP socket
    serverSocket.sendto(str(rand).encode(), clientAddress)

    # Receive the response from the client and compare it with xres
    chalAns, clientAddress = serverSocket.recvfrom(1024)
    res = chalAns.decode()

    # If the response matches xres, send the ck_a to the client over the UDP socket
    if res == xres: 
        serverSocket.sendto(ck_a.encode(), clientAddress)
        
    # If the response does not match xres, send an error message to the client over the UDP socket and break the loop
    else:
        msgFail = "Client not found. Aborting !!"
        serverSocket.sendto(msgFail.encode(), clientAddress)
        break

    print("Client authenticated !!")
randCookie = random.randint(1,10)
authSuccess = str(randCookie) + ',' + str(tcpPort)
# Create a random cookie and combine it with the TCP port number

connUser.append(clientID.decode())
# Append the client ID to the connUser list

b = base64.urlsafe_b64encode(bytes(ck_a, 'utf-8'))
# Encode the ck_a string in base64 format

cipher_suite = Fernet(b)
# Create a Fernet cipher suite with the encoded ck_a as key

print("Encrypting now !!")
authEnc = cipher_suite.encrypt(authSuccess.encode())
# Encrypt the authSuccess string with the Fernet cipher suite

serverSocket.sendto(authEnc, clientAddress)
# Send the encrypted message to the client address over the UDP socket

connect, clientAddress = serverTCP.accept()
# Accept a connection request over the TCP socket

print(f"Connected by {clientAddress}")
connect.send(f"You are now connected to {tcpAddress}".encode())
# Send a message to the client confirming the connection

threads.append(connect)
# Append the new thread to the threads list

thread = threading.Thread(target=threadTCP, args=(connect,))
thread.start()
# Start a new thread for the new TCP connection

serverSocket.close()
# Close the UDP socket

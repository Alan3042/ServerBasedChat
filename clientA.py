#!/usr/bin/env python3.8

# Import necessary modules
import socket
from socket import *
import hashlib
import base64
from cryptography.fernet import Fernet
import sys
import threading

# Define server details
serverName = 'hostname'
serverIP = "127.0.0.1"
serverPort = 12000
clientID = 'clientA'
key = 'a3c52bc7fd3a125e'

# Create a UDP socket
clientSocket = socket(AF_INET, SOCK_DGRAM)

# Function for receiving messages from the server
def receive(): 
    while True:
        try:
            # Receive message from server
            msg = clientSocket.recv(1024).decode()
            # Print message to console
            print(msg)
        except:
            # Close the socket and exit the program if an error occurs
            clientSocket.close()
            sys.exit()
            break

# Function for sending messages to the server
def write():
    while True:
        # Read input from console
        chat = input('')
        # Combine client ID and chat message
        msgChat = '{}: {}'.format(clientID, chat)
        # Send message to server
        clientSocket.send(msgChat.encode())
        # If user enters "Log off", send a disconnect message to server, close socket, and exit program
        if chat == "Log off":
            clientSocket.send(chat.encode())
            print("Disconnecting Now !!")
            clientSocket.close()
            sys.exit()
            break
        # If user enters "Chat<clientID>", send a connection request to the specified client
        if chat[:4] == "Chat":
            clientSocket.send(chat[-7:].encode())
            print("Please wait connecting to client !!")

# Send client ID to server
clientSocket.sendto(clientID.encode(), (serverIP, serverPort))

# Receive a random number from the server
randrecv, serverAddress = clientSocket.recvfrom(2048)
randcheck = randrecv.decode()

# Generate a hash of the random number concatenated with a secret key
hashSolve = str(randcheck)+key
h = hashlib.new('sha256')
h2 = hashlib.new('md5') #Needed for 32-byte key encryption
hashFunc = hashSolve.encode()
h.update(hashFunc)
h2.update(hashFunc)
ck_a = h2.hexdigest()

# Send hash to server for authentication
clientSocket.sendto(h.hexdigest().encode(), serverAddress)

# Receive authentication message from server
authMsg, serverAddress = clientSocket.recvfrom(1024)

# If client not found, print message to console, close socket, and exit program
if authMsg.decode() == 'Client not found. Aborting':
    print(authMsg.decode())
    clientSocket.close()
    sys.exit() 

# Decrypt authentication message and extract random number and TCP port number
cipher_suite = Fernet(base64.urlsafe_b64encode(bytes(ck_a, 'utf-8')))
authDec = cipher_suite.decrypt(authMsg).decode()
splitByComma = authDec.split(',')
randCookie = splitByComma[0]
serverTcp = splitByComma[1]

# Close UDP socket
clientSocket.close()

# Connect to server using TCP socket and send random number for confirmation
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverIP, int(serverTcp)))
clientSocket.send(randCookie.encode())
connected = clientSocket.recv(1024)

# Print confirmation message to console
print(connected.decode())

# Create two threads to handle receiving and sending messages
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

# ServerBasedChat

Project for UTD CS 4390

NOTE: Depending on your python version, you may need to modify "#! /usr/bin/env" to match the exact install. However this can be run easily with Python 3.

The server must first be run before any clients can connect. This can be done by executing "./server.py" (without quotes).
Once started, each client can connect by executing their respective program (e.g. clientA with "./clientA.py" and clientB with "./clientB.py"). The server will then go through the challenge/response and authentication procedures before connecting to the TCP chat server.

When the clients are connected, a chat can be initiated using the command Chat followed by the name of the client you want to chat with (e.g. Chat clientB). The server will check whether or not they are currently in a chat session.
If not, both clients will connect and they can communicate with each other. 

While in a chat, each user can view their current chat history by typing History, and the chat history will be displayed. 

To end a chat session, type end chat and you will be disconnected from the user and free to connect with other users

To disconnect from the server, type Log off

ServerBasedChat is a chat application built using Python that allows users to connect and communicate in real-time over the internet.

This application uses a client-server architecture, where the client is the browser-based Python chat interface, and the server is a Python server that handles the real-time communication between clients.

The project is open-source and available on GitHub at https://github.com/Alan3042/ServerBasedChat. Feel free to download and use the project code as a reference or contribute to the development of the application by submitting a pull request.


#

1. The Server must store each known client's public key in `{username}_public.pem`
    - Along with a folder named `{username}` to hold all of its emails(inbox)
2. 


## Protocols

### Server-Client Communication
[C] sends `username` and `password` encrypted with the **server public key** 

[S] Checks validity
- If yes:
    - generate `sym_key`(256 AES key), and send to client with corresponding **client public key**
    - print to server `"Connection Accepted and Symmetric Key Generated for client: {client_username}"`
- If no:
    - send __unencrypted__ message `"Invalid username or password"`
    - print to server `"The received client information: {client_username} is invalid (Connection Terminated)."`, then terminate connection

[C] receives response, print fail msg and terminate
[C] OR receives response, decrypt msg, store the `sym_key`, send the __encrypted__ msg `"OK"` to server using `sym_key`

[S] receives `"OK"`, sends menu __encrypted__

[C] receives and decrypts menu, takes input, sends encrypted input

[S]: decrypts msg,

    1. sending email subprotocol 
    2. viewing inbox subprotocol
    3. viewing email subprotocol
    Else: connection terminate subprotocol

**If connection not terminated loop**

### Sending email subprotocol
****BOTH Client and Server MUST check `title` and `content` fields for specifications, else reject it**
[S] encrypts the printable msg `"Send the email"` using `sym_key`

[C] receives, takes inputs for new email, sends encrypted email object

[S] receives, decrypts,
    - print to server `"An email from {client_username} is sent to [destination usernames] has a content length of {content_lenth}"`
    - **Add the current dateandtime** to email object
    - save the email in all destination client inboxes as `{client_username}_{email_title}.txt`

### Viewing Inbox subprotocol
[S] sends list of all client's emails sorted by date and time, each email should have `[index, source client username, date and time, and title]`

[C] receives, decrypts, prints, and sends server __encrypted__ `"OK"`

### Viewing email subprotocol
[S] sends encrypted msg `"the server equest email index"`

[C] takes input of email index, sends input

[S] receives, decrypts, retrieves email from index, and sends __encrypted__ email to client

[C] receives, decrypts, prints email

### Connection terminated subprotocol
[S] terminates, then prints to server `"Terminating connection with {username}"`
[C] terminates, prints `"The connection is terminated with the server"`


## All allowed imports
- `import json`
- `import socket`
- `import os`
- `import glob`
- `import datetime`
- `import sys`
- `import {any module from Crypto library}`
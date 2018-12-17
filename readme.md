# YASMS Server
## Installation
1. Ensure that you have **node.js** and **npm** installed on your machine
2. Clone the repo on your machine
3. Navigate to the folder where the repo has been cloned inside command prompt / powershell / terminal
4. Run the command `npm i`
## Usage
### Starting the Server
Inside the YASMS Server folder in your terminal of choice, run the command `node app.js CENTRALSERVERURL PORT`. Replace `CENTRALSERVERURL` with the path to the central server and `PORT` with the port you want the application server to run on. For example `node app.js http://localhost:3000 3010`.
The server will report to you what port it is running on.
### Making Requests
You'll need an app like [Postman](https://www.getpostman.com/) to make requests to the server.
### Available Operations
YASMS Server currently supports 6 operations:
#### 1. /ping
The `ping` operation is a POST-only operation. It responds with the server's status as online, and the server's communication and signing keys.
#### 2. /register
The `/register` operation is a POST-only operation. It allows a new user to be registered into the system.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key.

**_Message Parameters_**

**username**: The username of the user being registered.

**communication key**: The application communication key. This is used by the server to encrypt the response before sending it back.
#### 3. /updateaddress
The `/updateaddress` operation is a POST-only operation. It allows the user to update the address at which he is reachable. This command has no parameters as everything is done internally.
#### 4. /login
The `/login` operation is a POST-only operation. It allows a new user to be registered into the system.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key.

**_Message Parameters_**

**username**: The username of the user being logged in.

**keyfile**: The key file of the user being logged in.

**appsigningkey**: The public signing key of the application front end.

**appcommunicationkey**: The public communication key of the application front end.
#### 5. /addidentity
The `/addidentity` operation is a POST-only operation. It allows the user to add an identity to his existing list of identities.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**identityname**: The name of the identity being added.
#### 5. /getidentities
The `/getidentities` operation is a POST-only operation. It allows the user to get a list of his associated identities.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `getidentities`
#### 6. /sendchatrequest
The `/sendchatrequest` operation is a POST-only operation. It allows the user to send a chat request to a another user.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**identitynameto**: The identity name the chat request is being sent to.

**identitynamefrom**: The identity name the chat request is being sent from.
#### 7. /receivechatrequest
The `/receivechatrequest` operation is a POST-only operation. It allows the user to receive a chat request. This is used by the `/sendchatrequest` operation to receieve the request on the other side.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the user's public signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `requestchat`

**to**: The identity name the chat request is being sent to.

**from**: The identity name the chat request is being sent from.

**timestamp**: Epoch time at which command was issued. Command will only be processed if it is was issued in the past 5000 milliseconds.
#### 8. /getsentchatrequests
The `/getsentchatrequests` operation is a POST-only operation. It allows the user to get a list of sent pending chat requests.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `getsentchatrequests`
#### 9. /getreceivedchatrequests
The `/getreceivedchatrequests` operation is a POST-only operation. It allows the user to get a list of received pending chat requests.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `getreceivedchatrequests`
#### 10. /sendchatrequestresponse
The `/sendchatrequestresponse` operation is a POST-only operation. It allows the user to respond to a chat request.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**to**: The identity name the chat request is being sent to.

**from**: The identity name the chat request is being sent from.

**approved**: Whether or not the chat request has been approved.
#### 11. /receivechatrequestresponse
The `/receivechatrequestresponse` operation is a POST-only operation. It allows the user to receive a response to a chat request. This is used by the `/sendchatrequestresponse` operation to receieve the response on the other side.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the user's public signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `respondtochatrequest`

**receiver**: The identity name the chat request was sent to.

**sender**: The identity name the chat request was sent by.

**key**: The public key created by the receiver so that the sender can encrypt messages with.

**timestamp**: Epoch time at which command was issued. Command will only be processed if it is was issued in the past 5000 milliseconds.
**_Message Parameters_**

**command**: For this operation, the command should be `getreceivedchatrequests`
#### 12. /block
The `/block` operation is a POST-only operation. It allows the user to revoke a user's right to message.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**identitynamefrom**: The identity name being blocked.

**identitynameto**: The identity name doing the blocking.

**command**: For this operation, the command should be `block`
#### 13. /getcontacts
The `/getcontacts` operation is a POST-only operation. It allows the user to get a list of all contacts they are / were allowed to message.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `getcontacts`
#### 14. /cansend
The `/cansend` operation is a POST-only operation. It allows the user to check whether or not they can send to a specific identity.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `cansend`

**identitynamefrom**: The identity name being sent to.

**identitynameto**: The identity name sending.
#### 15. /sendmessage
The `/sendmessage` operation is a POST-only operation. It allows the user to send a message to another user.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**to**: The identity name the chat request is being sent to.

**from**: The identity name the chat request is being sent from.

**message**: The actual message text.

**command**: For this operation, the command should be `sendmessage`

**time**: The time at which the message was sent.
#### 16. /receivemessage
The `/receivemessage` operation is a POST-only operation. It allows the user to receive a message. This is used by the `/sendmessage` operation to receieve the message on the other side.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the user's public signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `sendmessage`

**receiver**: The identity name the message was sent to.

**sender**: The identity name the message was sent by.

**message**: The actual text of the messages.

**messagetime**: Epoch time at which message was created.
#### 17. /getmessages
The `/getmessages` operation is a POST-only operation. It allows the user to get a list of all messages exchanged between two defined identities.

**_Parameters_**

**message**: The command of the user. This is the string form of the JSON object represented by _Message Parameters_ below, encrypted with the app server's public communication key and signed with the app front end's private signing key.

**_Message Parameters_**

**command**: For this operation, the command should be `getmessages`

**persona**: One of the identities exchanging messages.

**personb**: The other identity exchanging messages.
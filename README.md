# TopChat
Topchat is a multi-threaded chat server written in C language.

### Features
- Multi threaded server to support multiple clients at once.
- Peer to Peer Chat
- Group Chat
- Account management
- File Database to store user information
- Secured messaging using both asymmetric and symmetric encryption

### Architecture
- The Chat Server have following APIs - Login API, Register API, Chat API.
- Server is configured to hold up to 10 client connections at once with separate thread for each connection.
- The client has two threads running in parallel, one for listening messages and other for sending messages.

### Peer to Peer Security flow
- For direct chat, we are using RSA encryption which is an asymmetric encryption algorithm.
- During registration of user, RSA public and private keys are generated.
- While sending the message, we encrypt the message on the client side with the public key of the recipient.
- Along with the encrypted message, we also send other information like sender id and recipient id which is used by server to deliver messages.
- On receiving on recipient, we decrypt it using private key of that client.

### Group Chat - Security flow
- For Group chat, we are using DES symmetric encryption algorithm.
- 64-bit DES key is pre shared with the clients.
- While sending and receiving messages, client simply uses this shared key to encrypt and decrypt messages respectively.
- Again, we also send other information like sender id and “ALL” tag which is used by server to deliver messages. 
- “ALL” tag denotes the message to be a broadcast message.

### Digital Signatures
- Along with message encryption, we also perform digital signature in both peer to peer and group chat.
- We use the client private key and message to generate the signature using openssl.
- The signature is then verified by the recipient using the sender public key.


### References
[WhatsApp‘s End to End Encryption, How does it work? | by Amit Panghal | Medium](https://medium.com/@panghalamit/whatsapp-s-end-to-end-encryption-how-does-it-work-80020977caa0)

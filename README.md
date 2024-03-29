#### This is an academic assignment where we applied security policies in a chat service. Consider it only for learning purposes.

# Table of Content

- [1. Introduction](#1-introduction)
- [2. Security Model](#2-security-model)
  * [2.1. Confidentiality](#21-confidentiality)
  * [2.2. Authenticity](#22-authenticity)
  * [2.3. Integrity](#23-integrity)
  * [2.4. Non-repudiation](#24-non-repudiation)
  * [2.5. Access Control](#25-access-control)
  * [2.6. Other security-related functionalities](#26-other-security-related-functionalities)
- [3. Implementation](#3-implementation)
  * [3.1. Certifications](#31-certifications)
  * [3.2. Signature](#32-signature)
  * [3.3. Message Content](#33-message-content)
- [4. Conclusions](#4-conclusions)

# 1. Introduction 

Security is one of the major concerns in the informatic technologies world. In this assignment, our task is implement a secure chat service in a ordinary client-server style system. The source code of the chat service is provided, however it does not provide any security policies. In order to apply those security policies, firstly we define the well-known security model used to identify and impose security policies. The security requirement are also provided, so the choice of the mechanics is a straight-forward task, since we are guided by the most widely used ones.
Besides the security model, we implemented each on of the described policies using the *Java* security (Application Programming Interface) API, since the system is written in the *Java* language. We included as security policies: certificates, symmetric encryption, message authentication code (MAC), digital signatures, dropping connections from certain sources and also key management features. These policies are described in the following section, as well as the configuration details.

In this section, we introduced the context and scope. The following section describes the security policies we imposed to ensure the fulfillment of the requirements. In section 3, we describe how we implemented the security model. Lastly, we provide brief conclusions regarding to this work.


# 2. Security Model 

The security model is used to identify and impose security policies. We pretend to ensure the following security attributes: confidentiality, authenticity, integrity, non-repudiation, access control and also other minor security-related functionalities. Thus, we describe each of the policies we choose to enforce security in the chat system.

## 2.1. Confidentiality

The messages exchanged between the participants in the chat should remain secret to the outside. Therefore, we use a symmetric encryption, where each client and server shares a unique key, meaning each client has a different key. The keys are generated by server using the *Advanced Encryption Standard* (AES) with a key-size of 192 bits. When a new clients successfully connects with the server, a key is generated and sent to the client. The AES encryption algorithm supports key-sizes of 128, 192 and 256 bits, we choose the 192 bits-size once 256 would be to heavy to apply in a online chat. Moreover, the block cipher mode of operation is *Cipher Block Chaining* (CBC) as it is the most commonly used mode. With this, we focused only on the confidentiality property, however the remaining properties are ensured using other mechanisms.

## 2.2. Authenticity

The Authenticity is guaranteed through the used of public-keys/certificates. Those keys are not exchange over the network like the symmetric encryption key. The signature algorithm of the keys is SHA256 with RSA. This is, the secure hash algorithm is SHA-256 bits and the RSA (Rivest–Shamir–Adleman) as the algorithm for the data encryption. Due to the increase in computational power the 1024-bit key can be broken, therefore we impose a key-size of 2048-bits.

## 2.3. Integrity

The data should not be tampered both when transferred from clients to servers, as well as the other way around. Thus, we send a Message Authentication Code (MAC) alongside each message. When someone within the system receives a message (i.e., a client or the server), it decrypts the message, generates a new MAC for the message received and compares with the MAC that comes within the message. If the values match, the message remains integral, otherwise it was tampered. In case of any message is tampered, the system will not perform any compensatory action, though in a real case, it will be necessary to work around this issue.

## 2.4. Non-repudiation

The non-repudiation is guaranteed through the use of signatures. Thus, we make use of the authenticity public and private keys to sign the messages transmitted between the server and the clients. The signature is sent together with the message as well as a customer identification. In order to send the signature the plain text should be signed using the private key of the sender and verified by the receiver, using the respective public key. These keys are stored in a key repository, also known as key store.

## 2.5. Access Control

The access control (AC) is a selective restriction of access to a certain resource or place, in this case to access the chat service. The connection from a set of source addresses is refused by the server. When launching the chat, IP addresses may be passed as arguments, every connection coming from those addresses is dropped.

## 2.6. Other security-related functionalities

The private and public keys are stored in a *KeyStore* local repository. Each *KeyStore* corresponds to a single entity repository, where its most confidential information (i.e., private key) is stored. No entity should access this information other than its owner.

# 3. Implementation

In this section, we abstract from the *Security Model* and describe our implementation procedures to fulfill the work requirements. We ignore the explanation of simpler implementation details with little relevance, such as how we drop the addresses to ensure the access control requirement.

## 3.1. Certifications
In order to implement both authenticity and non-repudiation, we use certificates. Those certificates were generated using the *Keytool* command line interface, a program from *Oracle* to manage keystore (database) of cryptographic keys, X.509 certificate chains, and trusted certificates. The following commands shows how to generate two *KeyStore* repositories for two entities, the server and a client, respectively.

~~~bash
$ keytool -genkeypair -alias plainserverkeys -keyalg RSA -dname "CN=Plain Server, OU=DEI, O=UC, L=Coimbra, ST=Coimbra, C=PT" -keypass password -keystore plainserver.jks -storepass password
$ keytool -genkeypair -alias plainclientkeys -keyalg RSA -dname "CN=Plain Server, OU=DEI, O=UC, L=Coimbra, ST=Coimbra, C=PT" -keypass password -keystore plainclient.jks -storepass password
~~~

Then, we exported the certificates that contains the public keys, required to validate the signatures in the counter-parts.

~~~bash
$ keytool -exportcert -alias plainserverkeys -file serverpub.cer -keystore plainserver.jks -storepass password
$ keytool -importcert -keystore serverpub.jks -alias serverpub -file serverpub.cer -storepass password

$ keytool -exportcert -alias plainclientkeys -file clientpub.cer -keystore plainclient.jks -storepass password
$ keytool -importcert -keystore clientpub.jks -alias clientpub -file clientpub.cer -storepass password
~~~

Finally, public certificates were imported to every *KeyStore*, that is, each entity (i.e., client or server) has only access to his repository. In order to verify the signatures, the entity verifies it against the public-keys saved in the repository. We directly exported the *KeyStore* data and imported in the others, to ease this process, however in a real project this is not so trivial.

~~~bash
$ keytool -importkeystore -srckeystore clientpub.jks -destkeystore plainserver.jks
$ keytool -importkeystore -srckeystore clientpub2.jks -destkeystore plainserver.jks
~~~

## 3.2. Signature

With the certificates generated in the previous sub-chapter, we are able to sign the messages using the private-keys and verify messages using the certificates/public-keys. The approach is simple, we loaded the keys from the *KeyStore* and used them to sign and verify the messages. Moreover, each message transmitted in addition to the signature, also contains the alias public name of the sender. This alias is the entry identification of the keys in the *KeyStore*, therefore if we know the alias, we can easily find the public key in the repository. 
A client sends a messages, this message is signed by the client, this is, his signature and alias is added to the cipher-text. The server receives it, validates and encrypts the message with his own signature and sends it to every client (signed by the server, not the original client).

## 3.3. Message Content

In this work, we have two kinds of message, the initial message where the server send a symmetric encryption key to the client encoded in base64 and the message with the actual information. This message can be broken in the following ordered parts: initialization vector + cipher-text + MAC + alias + signature. The IV and the symmetric encryption key are used to decrypt the cipher-text, then a MAC is calculated again and checked against the received one to figure if the message was tampered. Then, the alias is used to identify the message writer and find the public key to verify the signature to ensure both authenticity and non-repudiation.

# 4. Conclusions
Security is one of the major concerns in the informatics technologies world. In this work, we applied a set of security mechanisms to ensure security in a client-server application. Before implement those mechanisms, we designed the security model that describes the policies we choose to ensure the security requirements proposed to this work.
Both client and server applications are written in Java, so we were restricted to its security API, however this is probably one of the most widely used APIs to ensure security in server applications. 
The cipher-text is the only encrypted information in each message transmitted, the remaining data, IV, MAC, signature and alias are not encrypted, yet they are encoded in base64 format. Even the symmetric key to ensure integrity in sent in base64 format. This is a security vulnerability, every one can intercept the messages and tamper the signature, for instance. Moveover, we read the public-keys from the same \textit{KeyStore}, the server one, since we reuse most of the code produced to the client and server.

Our knowledge is short, regarding to the decisions to be made in choosing the best security solutions. As a learning outcome, we have learned how to apply the security mechanics on both ends of communication. Furthermore, every mechanism we used is widely known in the software industry.

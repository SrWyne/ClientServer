# Remote Shell (SSH Simulation) in C

> **Educational project** demonstrating the implementation of a simplified encrypted remote shell inspired by SSH using the POSIX API and OpenSSL.

## About

This project implements a basic client/server architecture capable of providing a remote shell session over TCP.

Unlike the real SSH protocol, this project **does not implement authentication, key exchange, host verification, compression or multiplexing**. Its purpose is to demonstrate the low-level concepts behind remote shell communication using C.

The implementation focuses on:

* TCP sockets
* Process creation (`fork`)
* Pseudo-terminals (`forkpty`)
* Terminal configuration (`termios`)
* Multiplexed I/O using `select()`
* Packet framing
* AES-256-GCM authenticated encryption with OpenSSL EVP API
* Nonce generation and transmission
* GCM authentication tags
* Remote shell interaction

---

# Project Structure

```text
.
├── client.c
├── server.c
└── README.md
```

---

# Features

* TCP client/server communication
* Interactive remote shell
* AES-256-GCM encrypted traffic
* Authenticated encryption using GCM authentication tags
* Unique nonce for encrypted messages
* Packet framing with size header
* Multiplexed I/O using `select()`
* Linux pseudo-terminal (PTY)
* Terminal raw mode on the server
* Automatic reconnection

---

# Server

The server waits for incoming TCP connections and acts as the operator.

Responsibilities:

* Creates a listening socket
* Accepts client connections
* Reads keyboard input
* Encrypts outgoing data using AES-256-GCM
* Generates a nonce for encryption
* Generates and sends the GCM authentication tag
* Sends encrypted packets
* Receives encrypted packets
* Verifies the authentication tag
* Decrypts authenticated data
* Displays shell output

### Main APIs

* `socket()`
* `bind()`
* `listen()`
* `accept()`
* `select()`
* `read()`
* `write()`
* `send()`
* `recv()`

---

## Terminal Configuration

The server places the terminal into **raw mode**.

This disables behavior such as:

* Canonical input processing
* Local echo

allowing every keystroke to be transmitted immediately, similar to an SSH session.

Functions used:

```text
tcgetattr()
tcsetattr()
```

---

## Packet Protocol

Each encrypted message contains the information required by AES-256-GCM, including:

* encrypted payload (ciphertext)
* nonce
* authentication tag
* framing information used to determine packet boundaries

Conceptually:

```text
+------------+----------+----------------------+----------+
| Length     | Nonce    | Ciphertext           | GCM Tag  |
+------------+----------+----------------------+----------+
```

The length field is encoded in network byte order.

Functions:

* `htonl()`
* `ntohl()`

Packet framing is necessary because TCP provides a **byte stream**, not discrete application-level messages. A single `send()` does not guarantee that the receiver obtains the same amount of data in a single `recv()`.

---

# Encryption

Communication is protected using:

```text
AES-256-GCM
```

through the OpenSSL EVP interface.

AES-256-GCM is an **AEAD (Authenticated Encryption with Associated Data)** mode. It provides both:

* **Confidentiality** — plaintext is encrypted into ciphertext.
* **Integrity/authenticity** — modification of protected data can be detected through the authentication tag.

The encryption process uses three important cryptographic values:

```text
Key + Nonce + Authentication Tag
```

### Key

AES-256 uses a **256-bit (32-byte) symmetric key**.

The same secret key is required for encryption and decryption.

### Nonce

GCM requires a nonce that must not be reused with the same key.

A new nonce is therefore used for encrypted messages and transmitted together with the ciphertext so the receiving side can perform decryption.

### Authentication Tag

During encryption, GCM generates an authentication tag.

The receiver supplies this tag during decryption. If the ciphertext or other authenticated data has been modified, authentication fails and the plaintext must be rejected.

### Encryption

The OpenSSL EVP encryption flow uses functions such as:

```text
EVP_EncryptInit_ex()
EVP_EncryptUpdate()
EVP_EncryptFinal_ex()
EVP_CIPHER_CTX_ctrl()
```

The GCM authentication tag is obtained after encryption using the appropriate `EVP_CIPHER_CTX_ctrl()` operation.

### Decryption

Incoming packets are decrypted and authenticated using functions such as:

```text
EVP_DecryptInit_ex()
EVP_DecryptUpdate()
EVP_CIPHER_CTX_ctrl()
EVP_DecryptFinal_ex()
```

Before finalizing decryption, the received authentication tag is supplied to the GCM context.

If authentication fails, the received plaintext must not be trusted or processed.

---

# Client

The client establishes a TCP connection with the server.

After establishing the connection it:

* launches a Bash shell inside a pseudo-terminal
* forwards shell output to the server
* receives encrypted data from the server
* authenticates and decrypts received packets
* forwards received input to the pseudo-terminal
* encrypts shell output using AES-256-GCM
* reconnects automatically if the connection closes

The client **does not daemonize itself** and does not use the classic double-fork daemonization procedure.

---

## Pseudo Terminal (PTY)

Instead of directly connecting pipes to `/bin/bash`, the client creates a pseudo-terminal using:

```text
forkpty()
```

The PTY provides terminal semantics required by interactive shell applications.

Advantages include:

* Proper shell prompts
* Interactive programs
* Terminal-oriented input/output
* Job-control support
* Behavior closer to a normal interactive terminal

`forkpty()` creates a pseudo-terminal pair and forks the process.

The parent communicates through the **PTY master**, while the child receives a terminal environment through the **PTY slave**.

---

## Shell Execution

Inside the PTY child process, the client executes:

```text
/bin/bash
```

using:

```text
execl()
```

The shell process is therefore attached to the PTY slave.

The client reads shell output through the PTY master descriptor, encrypts it and transmits it through the TCP connection.

Data received from the server follows the opposite direction:

```text
TCP socket
    ↓
AES-256-GCM authentication/decryption
    ↓
PTY master
    ↓
PTY slave
    ↓
/bin/bash
```

---

## Event Loop

The client simultaneously monitors:

* TCP socket
* pseudo-terminal master

using:

```text
select()
```

This allows bidirectional communication without continuously polling each file descriptor in a busy loop.

When the socket becomes readable, network data can be received and forwarded to the PTY.

When the PTY becomes readable, shell output can be encrypted and transmitted to the server.

---

# Communication Flow

```text
Operator
     │
     ▼
Server Keyboard
     │
     ▼
AES-256-GCM
Encrypt + Tag
     │
     ▼
Nonce + Ciphertext + Tag
     │
     ▼
TCP Socket
     │
     ▼
Verify Tag + Decrypt
     │
     ▼
PTY Master
     │
     ▼
PTY Slave
     │
     ▼
/bin/bash
     │
     ▼
Command Output
     │
     ▼
AES-256-GCM
Encrypt + Tag
     │
     ▼
Nonce + Ciphertext + Tag
     │
     ▼
TCP Socket
     │
     ▼
Verify Tag + Decrypt
     │
     ▼
Server Terminal
```

---

# Building

Requirements:

* GCC
* OpenSSL
* Linux
* libutil

Compile the server:

```bash
gcc server.c -o server -lssl -lcrypto
```

Compile the client:

```bash
gcc client.c -o client -lutil -lssl -lcrypto
```

---

# Running

Server:

```bash
./server
```

Client:

```bash
./client
```

---

# Limitations

This project is intentionally simplified and **must not be considered a replacement for SSH**.

It does **not** implement:

* SSH protocol
* Secure key exchange
* Public/private key authentication
* Password authentication
* Host verification
* Forward secrecy
* Compression
* Port forwarding
* Multiplexing

Although AES-GCM provides an authentication tag as part of its AEAD construction, this does **not** provide SSH-style peer authentication or identity verification.

If the symmetric AES-256 key is statically defined in the source code, this is also an important security limitation. The project does not implement a secure protocol for negotiating or distributing that key.

Nonce uniqueness is also critical when AES-GCM is used. **Reusing a nonce with the same AES key can severely compromise the security of GCM.**

For these reasons, the cryptographic implementation exists primarily to demonstrate low-level concepts involving encrypted network communication and authenticated encryption.

---

# Educational Concepts

This project demonstrates:

* Linux sockets
* TCP communication
* TCP stream handling
* Packet framing
* OpenSSL EVP API
* AES-256
* Galois/Counter Mode (GCM)
* Authenticated Encryption with Associated Data (AEAD)
* Symmetric encryption keys
* Nonces
* Authentication tags
* Ciphertext integrity verification
* Network byte order
* POSIX terminals
* Pseudo-terminals (PTYs)
* Process creation
* Shell execution
* File descriptors
* Multiplexed I/O with `select()`
* Remote shell architecture

---

# License

This repository is intended exclusively for educational purposes in operating systems, computer networks and applied cryptography studies.

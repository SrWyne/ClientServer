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
* AES-128-CBC encryption with OpenSSL EVP API
* Daemon creation
* Remote shell interaction

---

# Project Structure

```
.
├── client.c
├── server.c
└── README.md
```

---

# Features

* TCP client/server communication
* Interactive remote shell
* AES-128-CBC encrypted traffic
* Packet framing with size header
* Non-blocking I/O using `select()`
* Linux pseudo-terminal (PTY)
* Daemonized client
* Terminal raw mode on the server
* Automatic reconnection

---

# Server

The server waits for incoming TCP connections and acts as the operator.

Responsibilities:

* Creates a listening socket
* Accepts client connections
* Reads keyboard input
* Encrypts outgoing data
* Sends encrypted packets
* Receives encrypted packets
* Decrypts received data
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

This disables:

* Canonical mode
* Local echo

allowing every keystroke to be transmitted immediately, similar to an SSH session.

Functions used:

```
tcgetattr()
tcsetattr()
```

---

## Packet Protocol

Each packet is transmitted using the following format:

```
+------------+----------------------+
| 4 bytes    | encrypted payload    |
+------------+----------------------+
```

The first four bytes contain the payload length encoded in network byte order.

Functions:

* `htonl()`
* `ntohl()`

This guarantees that complete encrypted messages are received even if TCP splits them into multiple segments.

---

## Encryption

The server encrypts every outgoing packet using:

```
AES-128-CBC
```

through the OpenSSL EVP interface.

Functions:

* `EVP_EncryptInit_ex()`
* `EVP_EncryptUpdate()`
* `EVP_EncryptFinal_ex()`

Incoming packets are decrypted using:

* `EVP_DecryptInit_ex()`
* `EVP_DecryptUpdate()`
* `EVP_DecryptFinal_ex()`

---

# Client

The client runs silently as a background daemon.

It continuously attempts to connect to the server.

After establishing the connection it:

* launches a Bash shell inside a pseudo-terminal
* forwards shell output to the server
* executes commands received from the server
* reconnects automatically if the connection closes

---

## Daemon Mode

The client detaches from the terminal using the classic double-fork daemonization technique.

Steps:

1. First fork
2. Create new session (`setsid`)
3. Second fork
4. Close stdin/stdout/stderr
5. Redirect descriptors to `/dev/null`

Functions:

```
fork()
setsid()
umask()
chdir()
dup()
open()
```

---

## Pseudo Terminal (PTY)

Instead of directly spawning `/bin/bash`, the client creates a pseudo-terminal using:

```
forkpty()
```

This provides behavior almost identical to an interactive Linux terminal.

Advantages:

* Proper prompts
* Interactive programs
* Job control
* Terminal behavior similar to SSH

---

## Shell Execution

Inside the PTY the client executes:

```
/bin/bash
```

using

```
execl()
```

The shell output is read from the PTY master descriptor and transmitted through the encrypted socket.

---

## Event Loop

The client simultaneously monitors:

* socket
* pseudo-terminal

using

```
select()
```

This allows bidirectional communication without busy waiting.

---

# Communication Flow

```
Operator
     │
     ▼
Server Keyboard
     │
Encrypt
     │
TCP Socket
     │
Decrypt
     │
Pseudo Terminal
     │
/bin/bash
     │
Command Output
     │
Encrypt
     │
TCP Socket
     │
Decrypt
     │
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

This project is intentionally simplified.

It does **not** implement:

* SSH protocol
* Key exchange
* Public/private key authentication
* Password authentication
* Host verification
* Forward secrecy
* MAC authentication
* Compression
* Port forwarding
* Multiplexing

The symmetric AES key and IV are statically defined only for educational purposes.

---

# Educational Concepts

This project demonstrates:

* Linux sockets
* TCP communication
* Packet framing
* OpenSSL EVP API
* AES encryption
* Network byte order
* POSIX terminals
* PTYs
* Daemon processes
* Process management
* Multiplexed I/O
* Remote shell architecture

---

# License

This repository is intended exclusively for educational purposes in operating systems, computer networks and applied cryptography studies.

# CS441  G2T1

This project simulates a network of nodes and a router communicating securely over UDP using Diffie-Hellman key exchange for shared secret derivation. Each node independently establishes shared keys with peers to encrypt and decrypt messages securely.

## Project Structure

| File         | Description                                                      |
|--------------|------------------------------------------------------------------|
| `Router.py`  | Handles message forwarding between nodes using UDP.              |
| `Node.py`    | Defines a generic Node class to send/receive encrypted messages. |
| `Node1.py`   | Script for running Node 1 instance.                              |
| `Node2.py`   | Script for running Node 2 instance.                              |
| `Node3.py`   | Script for running Node 3 instance.                              |
| `dhparams.py`| Defines DH parameters (prime, generator) and helper functions.   |
| `/network` | Contain Frame, Packet and TCPHeader Classes                        |
| `requirements.txt` | Lists the Python package dependencies.                     |

## Installation

1. **Clone the repository** (or download the files).
2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

> Requires `cryptography==41.0.7`.

## Usage

1. **Start the Router and Nodes in different Terminals**:

```bash
python Router.py
python Node1.py
python Node2.py
python Node3.py
```

2. **Follow commands as laid out in Node command line**


## Requirements

- Python 3.8+
- cryptography==41.0.7

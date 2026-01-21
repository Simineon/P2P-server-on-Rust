# P2P Server Structure

 ## Overview
 This module implements a peer-to-peer (P2P) server with RSA encryption support.
 The server handles incoming connections and can also initiate outgoing connections
 to other peers, forming a mesh network.

 ## Key Components

 ### Log Structure
 Handles logging to both console and file with timestamps.

 ### P2P Server Structure
 Main server structure containing:
 - Network configuration (host, port, max clients)
 - Client management (IPs, sockets, busy flags)
 - Cryptography (RSA key pairs for each connection)
 - Message queues for incoming requests
 - Blacklist and connection attempt tracking

 ## Architecture

 ### Threading Model
 - Main thread: Accepts incoming connections
 - Worker threads: One per connected client for message handling

 ### Connection Flow
 1. Connection established (incoming or outgoing)
 2. RSA key exchange (each side sends public key)
 3. Slot allocation in client pool
 4. Continuous message processing

 ### Message Encryption
 - Outgoing: Encrypted with peer's public key
 - Incoming: Decrypted with our private key
 - Uses RSA with PKCS1v15 padding (512-bit keys)

 ## Data Structures

 ### Shared State (Arc<Mutex<T>>)
 - `clients_ip`: Vector of client IP addresses
 - `client_sockets`: Vector of shared TCP streams
 - `incoming_requests`: HashMap of message queues per client
 - `keys/my_keys`: RSA public/private keys for each connection

 ## API Methods

 ### Server Management
 - `new()`: Initialize server
 - `start()`: Begin accepting connections
 - `kill_server()`: Graceful shutdown

 ### Connection Management
 - `create_session()`: Connect to another peer
 - `close_connection()`: Disconnect from peer
 - `check_address()`: Verify if connected to peer

 ### Message Handling
 - `send()`: Send encrypted message
 - `raw_send()`: Send raw bytes
 - `get_request()`: Retrieve incoming message
 - `check_request()`: Check for pending messages

 ## Security Features

 ### Blacklist System
 - Loads IPs from `blacklist.txt`
 - Rejects connections from blacklisted IPs

 ### Connection Flood Protection
 - Tracks connection attempts with timestamps
 - Prevents duplicate connections within 5-second window

 ## Usage Example
 ```rust
 let mut server = P2P::new(8080, 10)?;
 server.start();

 // Connect to another peer
 server.create_session("192.168.1.100", Some(8080));

 // Send message
 server.send("192.168.1.100", "Hello, peer!");

 // Check for incoming messages
 if server.check_request("192.168.1.100") {
     let msg = server.get_request("192.168.1.100").unwrap();
 }
 ```
 ## Limitations
 - Fixed-size client pool (set at initialization)
 - Single listener thread
 - No connection retry mechanism
 - Basic RSA implementation (consider stronger crypto)

 Author: Simineon - https://github.com/Simineon/
 License: GPL-3.0-or-later

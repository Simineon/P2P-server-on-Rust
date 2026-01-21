//! # P2P Server Structure
//!
//! ## Overview
//! This module implements a peer-to-peer (P2P) server with RSA encryption support.
//! The server handles incoming connections and can also initiate outgoing connections
//! to other peers, forming a mesh network.
//!
//! ## Key Components
//!
//! ### Log Structure
//! Handles logging to both console and file with timestamps.
//!
//! ### P2P Server Structure
//! Main server structure containing:
//! - Network configuration (host, port, max clients)
//! - Client management (IPs, sockets, busy flags)
//! - Cryptography (RSA key pairs for each connection)
//! - Message queues for incoming requests
//! - Blacklist and connection attempt tracking
//!
//! ## Architecture
//!
//! ### Threading Model
//! - Main thread: Accepts incoming connections
//! - Worker threads: One per connected client for message handling
//!
//! ### Connection Flow
//! 1. Connection established (incoming or outgoing)
//! 2. RSA key exchange (each side sends public key)
//! 3. Slot allocation in client pool
//! 4. Continuous message processing
//!
//! ### Message Encryption
//! - Outgoing: Encrypted with peer's public key
//! - Incoming: Decrypted with our private key
//! - Uses RSA with PKCS1v15 padding (512-bit keys)
//!
//! ## Data Structures
//!
//! ### Shared State (Arc<Mutex<T>>)
//! - `clients_ip`: Vector of client IP addresses
//! - `client_sockets`: Vector of shared TCP streams
//! - `incoming_requests`: HashMap of message queues per client
//! - `keys/my_keys`: RSA public/private keys for each connection
//!
//! ## API Methods
//!
//! ### Server Management
//! - `new()`: Initialize server
//! - `start()`: Begin accepting connections
//! - `kill_server()`: Graceful shutdown
//!
//! ### Connection Management
//! - `create_session()`: Connect to another peer
//! - `close_connection()`: Disconnect from peer
//! - `check_address()`: Verify if connected to peer
//!
//! ### Message Handling
//! - `send()`: Send encrypted message
//! - `raw_send()`: Send raw bytes
//! - `get_request()`: Retrieve incoming message
//! - `check_request()`: Check for pending messages
//!
//! ## Security Features
//!
//! ### Blacklist System
//! - Loads IPs from `blacklist.txt`
//! - Rejects connections from blacklisted IPs
//!
//! ### Connection Flood Protection
//! - Tracks connection attempts with timestamps
//! - Prevents duplicate connections within 5-second window
//!
//! ## Usage Example
//! ```rust
//! let mut server = P2P::new(8080, 10)?;
//! server.start();
//!
//! // Connect to another peer
//! server.create_session("192.168.1.100", Some(8080));
//!
//! // Send message
//! server.send("192.168.1.100", "Hello, peer!");
//!
//! // Check for incoming messages
//! if server.check_request("192.168.1.100") {
//!     let msg = server.get_request("192.168.1.100").unwrap();
//! }
//! ```
//!
//! ## Limitations
//! - Fixed-size client pool (set at initialization)
//! - Single listener thread
//! - No connection retry mechanism
//! - Basic RSA implementation (consider stronger crypto)
//!
//! Author: Simineon - https://github.com/Simineon/
//!
//! License: GPL-3.0-or-later
//! ```
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rand::rngs::OsRng;
use hightower_stun::client::StunClient;

pub struct Log {
    name: String,
}

impl Log {
    pub fn new(name: &str) -> Self {
        println!("[LOG] Log started for: {}", name);

        let _ = fs::create_dir_all("logs");

        Log {
            name: name.to_string(),
        }
    }

    pub fn save_data(&self, data: &str) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_message = format!("[{}] {}", timestamp, data);

        println!("[LOG:{}] {}", self.name, data);

        let file_path = format!("logs/{}", self.name);
        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", log_message) {
                    eprintln!("Failed to write to log file {}: {}", file_path, e);
                }
            }
            Err(e) => {
                eprintln!("Failed to open log file {}: {}", file_path, e);
            }
        }
    }

    pub fn kill_log(&self) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_message = format!("[{}] Log stopped", timestamp);

        let file_path = format!("logs/{}", self.name);
        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", log_message) {
                    eprintln!("Failed to write to log file {}: {}", file_path, e);
                }
            }
            Err(e) => {
                eprintln!("Failed to open log file {}: {}", file_path, e);
            }
        }

        println!("[LOG:{}] Log stopped", self.name);
    }
}

type SharedTcpStream = Arc<Mutex<TcpStream>>;

pub struct P2P {
    // Base
    running: Arc<Mutex<bool>>,
    port: u16,
    host: String,
    bind_ip: String,
    max_clients: usize,
    clients_ip: Arc<Mutex<Vec<String>>>,
    incoming_requests: Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>>,
    client_sockets: Arc<Mutex<Vec<Option<SharedTcpStream>>>>,
    socket_busy: Arc<Mutex<Vec<bool>>>,
    // Keys
    keys: Arc<Mutex<Vec<Option<RsaPublicKey>>>>,
    my_keys: Arc<Mutex<Vec<Option<RsaPrivateKey>>>>,
    // accessories
    listener: TcpListener,
    accept_thread: Option<thread::JoinHandle<()>>,
    log: Arc<Log>,
    blacklist: Arc<Vec<String>>,
    connection_attempts: Arc<Mutex<HashMap<String, std::time::Instant>>>,
}

impl P2P {
    pub fn new(port: u16, max_clients: usize) -> io::Result<Self> {
        let public_ip = Self::get_public_ip().unwrap_or_else(|_| {
            println!("Unable to get public IP, will use local IP for connections");
            String::new()
        });

        let local_ip = Self::get_local_ip_fallback();
        println!("Local IP for binding: {}", local_ip);
        println!("Public IP for sharing: {}", if public_ip.is_empty() { "Unknown" } else { &public_ip });

        let bind_ip = if local_ip == "127.0.0.1" {
            "0.0.0.0"
        } else {
            &local_ip
        };

        let listener = TcpListener::bind((bind_ip, port))?;
        listener.set_nonblocking(true)?;

        let log = Arc::new(Log::new("server.log"));
        log.save_data(&format!("Server initialized on {}:{} (public IP: {})",
                               bind_ip, port,
                               if public_ip.is_empty() { "unknown" } else { &public_ip }));

        let blacklist = Arc::new(Self::read_blacklist("blacklist.txt"));

        Ok(P2P {
            running: Arc::new(Mutex::new(true)),
            port,
            host: public_ip,
            bind_ip: local_ip,
            max_clients,
            clients_ip: Arc::new(Mutex::new(vec![String::new(); max_clients])),
            incoming_requests: Arc::new(Mutex::new(HashMap::new())),
            client_sockets: Arc::new(Mutex::new(vec![None; max_clients])),
            socket_busy: Arc::new(Mutex::new(vec![false; max_clients])),
            keys: Arc::new(Mutex::new(vec![None; max_clients])),
            my_keys: Arc::new(Mutex::new(vec![None; max_clients])),
            listener,
            accept_thread: None,
            log,
            blacklist,
            connection_attempts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn read_blacklist(filename: &str) -> Vec<String> {
        match fs::read_to_string(filename) {
            Ok(contents) => contents
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn get_public_ip() -> Result<String, Box<dyn std::error::Error>> {
        let services = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
            "https://checkip.amazonaws.com",
            "https://ipinfo.io/ip",
        ];

        for service in services.iter() {
            match Self::fetch_ip_from_service(service) {
                Ok(ip) if Self::is_valid_public_ip(&ip) => {
                    println!("Got public IP by {}: {}", service, ip);
                    return Ok(ip);
                }
                Ok(_) => continue,
                Err(e) => {
                    println!("Error by {}: {}", service, e);
                    continue;
                }
            }
        }

        Err("Can't get public IP".into())
    }

    fn fetch_ip_from_service(url: &str) -> Result<String, Box<dyn std::error::Error>> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Parse URL
        let url = url.replace("https://", "");
        let (host, path) = if let Some(idx) = url.find('/') {
            (&url[..idx], &url[idx..])
        } else {
            (&url[..], "/")
        };

        let port = if url.starts_with("https://") { 443 } else { 80 };
        let host_with_port = if port == 443 {
            format!("{}:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };

        let mut stream = TcpStream::connect(&host_with_port)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        // HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
            Host: {}\r\n\
            User-Agent: P2P-Client/1.0\r\n\
            Connection: close\r\n\
            Accept: */*\r\n\r\n",
            path, host
        );

        stream.write_all(request.as_bytes())?;

        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let response_str = String::from_utf8_lossy(&response);

        let ip = response_str
            .lines()
            .last()
            .unwrap_or("")
            .trim()
            .to_string();

        if ip.is_empty() {
            return Err("Пустой ответ".into());
        }

        Ok(ip)
    }

    fn is_valid_public_ip(ip: &str) -> bool {
        use std::net::Ipv4Addr;

        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
            !(
                ipv4.is_private() ||      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    ipv4.is_loopback() ||     // 127.0.0.0/8
                    ipv4.is_link_local() ||   // 169.254.0.0/16
                    ipv4.is_broadcast() ||    // 255.255.255.255
                    ipv4.is_unspecified()     // 0.0.0.0
            )
        } else {
            false
        }
    }

    fn get_local_ip_fallback() -> String {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if let Ok(()) = socket.connect("8.8.8.8:80") {
                if let Ok(addr) = socket.local_addr() {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            return ipv4.to_string();
                        }
                    }
                }
            }
        }

        if let Ok(interfaces) = get_if_addrs::get_if_addrs() {
            for interface in interfaces {
                if interface.is_loopback() { continue; }
                if let get_if_addrs::IfAddr::V4(ipv4) = interface.addr {
                    if ipv4.ip.is_private() {
                        return ipv4.ip.to_string();
                    }
                }
            }
        }

        "0.0.0.0".to_string()
    }

    // getting local ip (connection by wi-fi)
    // fn get_local_ip_str() -> String {
    //     if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
    //         if let Ok(()) = socket.connect("8.8.8.8:80") {
    //             if let Ok(addr) = socket.local_addr() {
    //                 if let std::net::IpAddr::V4(ipv4) = addr.ip() {
    //                     if !ipv4.is_loopback() && !ipv4.is_unspecified() {
    //                         return ipv4.to_string();
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //
    //     if let Ok(listener) = TcpListener::bind("0.0.0.0:0") {
    //         if let Ok(addr) = listener.local_addr() {
    //             if let std::net::IpAddr::V4(ipv4) = addr.ip() {
    //                 if !ipv4.is_loopback() {
    //                     return ipv4.to_string();
    //                 }
    //             }
    //         }
    //     }
    //
    //     if let Ok(hostname) = hostname::get() {
    //         if let Ok(addrs) = (hostname.to_string_lossy() + ":0").to_socket_addrs() {
    //             for addr in addrs {
    //                 if let std::net::IpAddr::V4(ipv4) = addr.ip() {
    //                     if !ipv4.is_loopback() && !ipv4.is_unspecified() {
    //                         return ipv4.to_string();
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //
    //     "127.0.0.1".to_string()
    // }

    pub fn start(&mut self) {
        let bind_addr = if self.bind_ip == "0.0.0.0" {
            format!("all interfaces:{}", self.port)
        } else {
            format!("{}:{}", self.bind_ip, self.port)
        };

        println!("Server started on {}", bind_addr);

        let public_ip_info = if self.host.is_empty() {
            "unknown public IP".to_string()
        } else {
            format!("public IP: {}", self.host)
        };

        println!("Share your {} with other peers to connect", public_ip_info);
        self.log.save_data(&format!("Server bound to {}", bind_addr));
        self.log.save_data(&format!("Public IP for sharing: {}",
                                    if self.host.is_empty() { "unknown" } else { &self.host }));

        self.accept_thread = Some(self.accept_connections());
        println!("Server started successfully!");
        println!("Waiting for connections...");
        self.log.save_data("Server started successfully!");
    }

    fn accept_connections(&self) -> thread::JoinHandle<()> {
        let running = Arc::clone(&self.running);
        let listener = self.listener.try_clone().unwrap();
        let clients_ip = Arc::clone(&self.clients_ip);
        let incoming_requests = Arc::clone(&self.incoming_requests);
        let client_sockets = Arc::clone(&self.client_sockets);
        let socket_busy = Arc::clone(&self.socket_busy);
        let keys = Arc::clone(&self.keys);
        let my_keys = Arc::clone(&self.my_keys);
        let log = Arc::clone(&self.log);
        let blacklist = Arc::clone(&self.blacklist);
        let connection_attempts = Arc::clone(&self.connection_attempts);
        let max_clients = self.max_clients;
        let host = self.host.clone();
        let port = self.port;

        thread::spawn(move || {
            log.save_data(&format!(
                "Server started on {}:{}, accepting connections...(Press Enter or Return to continue)",
                host, port
            ));

            while *running.lock().unwrap() {
                match listener.accept() {
                    Ok((mut stream, addr)) => {
                        log.save_data(&format!("Incoming connection from {}", addr.ip()));

                        if blacklist.contains(&addr.ip().to_string()) {
                            log.save_data(&format!("{} is in blacklist, rejecting", addr.ip()));
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }

                        let running_clone = Arc::clone(&running);
                        let clients_ip_clone = Arc::clone(&clients_ip);
                        let incoming_requests_clone = Arc::clone(&incoming_requests);
                        let client_sockets_clone = Arc::clone(&client_sockets);
                        let socket_busy_clone = Arc::clone(&socket_busy);
                        let keys_clone = Arc::clone(&keys);
                        let my_keys_clone = Arc::clone(&my_keys);
                        let log_clone = Arc::clone(&log);
                        let connection_attempts_clone = Arc::clone(&connection_attempts);

                        thread::spawn(move || {
                            Self::handle_incoming(
                                stream,
                                addr,
                                running_clone,
                                clients_ip_clone,
                                incoming_requests_clone,
                                client_sockets_clone,
                                socket_busy_clone,
                                keys_clone,
                                my_keys_clone,
                                log_clone,
                                connection_attempts_clone,
                                max_clients,
                            );
                        });
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(200));
                        continue;
                    }
                    Err(e) => {
                        if *running.lock().unwrap() {
                            log.save_data(&format!("Accept error: {}", e));
                        }
                        continue;
                    }
                }
            }
            log.save_data("Server stopped accepting connections");
        })
    }

    fn handle_incoming(
        mut stream: TcpStream,
        addr: SocketAddr,
        running: Arc<Mutex<bool>>,
        clients_ip: Arc<Mutex<Vec<String>>>,
        incoming_requests: Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>>,
        client_sockets: Arc<Mutex<Vec<Option<SharedTcpStream>>>>,
        socket_busy: Arc<Mutex<Vec<bool>>>,
        keys: Arc<Mutex<Vec<Option<RsaPublicKey>>>>,
        my_keys: Arc<Mutex<Vec<Option<RsaPrivateKey>>>>,
        log: Arc<Log>,
        connection_attempts: Arc<Mutex<HashMap<String, std::time::Instant>>>,
        max_clients: usize,
    ) {
        let addr_str = addr.ip().to_string();

        {
            let mut attempts = connection_attempts.lock().unwrap();
            if let Some(last_attempt) = attempts.get(&addr_str) {
                if last_attempt.elapsed() < Duration::from_secs(5) {
                    log.save_data(&format!("Connection attempt to {} is already in progress, rejecting duplicate", addr_str));
                    return;
                }
            }
            attempts.insert(addr_str.clone(), std::time::Instant::now());
        }

        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

        // 1. Getting public key by client
        let mut key_buf = [0u8; 1024];
        let key_size = match Self::read_with_timeout(&mut stream, &mut key_buf, Duration::from_secs(5)) {
            Ok(size) => size,
            Err(e) => {
                log.save_data(&format!("Key read error from {}: {}", addr_str, e));
                return;
            }
        };

        if key_size == 0 {
            log.save_data(&format!("Empty key from {}", addr_str));
            return;
        }

        let client_key = match RsaPublicKey::from_pkcs1_der(&key_buf[..key_size]) {
            Ok(key) => key,
            Err(e) => {
                log.save_data(&format!("Invalid key from {}: {}", addr_str, e));
                return;
            }
        };

        log.save_data(&format!("Received key from {}", addr_str));

        // 2. Generating self keys and send public key back
        let mut rng = OsRng;
        let private_key = match RsaPrivateKey::new(&mut rng, 512) {
            Ok(key) => key,
            Err(e) => {
                log.save_data(&format!("Private key generation error: {}", e));
                return;
            }
        };

        let public_key = RsaPublicKey::from(&private_key);
        let pub_key_der = match public_key.to_pkcs1_der() {
            Ok(der) => der,
            Err(e) => {
                log.save_data(&format!("Public key serialization error: {}", e));
                return;
            }
        };

        if let Err(e) = stream.write_all(pub_key_der.as_bytes()) {
            log.save_data(&format!("Error sending our key to {}: {}", addr_str, e));
            return;
        }

        // 3. Adding peer
        let slot_idx = {
            let mut clients_ip_guard = clients_ip.lock().unwrap();
            let mut socket_busy_guard = socket_busy.lock().unwrap();

            let mut free_slot = None;
            for i in 0..max_clients {
                if clients_ip_guard[i].is_empty() && !socket_busy_guard[i] {
                    free_slot = Some(i);
                    break;
                }
            }

            match free_slot {
                Some(idx) => {
                    clients_ip_guard[idx] = addr_str.clone();
                    socket_busy_guard[idx] = true;
                    idx
                }
                None => {
                    log.save_data(&format!("No free slots for {}", addr_str));
                    return;
                }
            }
        };

        // Saving socket and keys
        {
            let mut client_sockets_guard = client_sockets.lock().unwrap();
            client_sockets_guard[slot_idx] = Some(Arc::new(Mutex::new(stream.try_clone().unwrap())));

            let mut keys_guard = keys.lock().unwrap();
            keys_guard[slot_idx] = Some(client_key);

            let mut my_keys_guard = my_keys.lock().unwrap();
            my_keys_guard[slot_idx] = Some(private_key);
        }

        log.save_data(&format!("Added incoming user {}", addr_str));

        {
            let mut attempts = connection_attempts.lock().unwrap();
            attempts.remove(&addr_str);
        }

        if let Err(e) = stream.set_nonblocking(true) {
            log.save_data(&format!("Failed to set non-blocking for {}: {}", addr_str, e));
        }

        // 4. Hearing message by client
        let mut buf = [0u8; 2048];

        while *running.lock().unwrap() && socket_busy.lock().unwrap()[slot_idx] {
            match stream.read(&mut buf) {
                Ok(0) => break, // Connection closed
                Ok(size) => {
                    let my_key_guard = my_keys.lock().unwrap();
                    if let Some(ref my_key) = my_key_guard[slot_idx] {
                        match my_key.decrypt(Pkcs1v15Encrypt, &buf[..size]) {
                            Ok(decrypted) => {
                                let mut requests_guard = incoming_requests.lock().unwrap();
                                requests_guard
                                    .entry(addr_str.clone())
                                    .or_insert_with(VecDeque::new)
                                    .push_back(decrypted);

                                log.save_data(&format!("Received message from {}", addr_str));
                            }
                            Err(e) => {
                                log.save_data(&format!("Decrypt error from {}: {}", addr_str, e));
                                break;
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    log.save_data(&format!("Read error from {}: {}", addr_str, e));
                    break;
                }
            }
        }

        // Close connection
        Self::close_connection_internal(
            &addr_str,
            slot_idx,
            clients_ip,
            incoming_requests,
            client_sockets,
            socket_busy,
            keys,
            my_keys,
            log,
        );
    }

    fn read_with_timeout(stream: &mut TcpStream, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let start = std::time::Instant::now();

        loop {
            match stream.read(buf) {
                Ok(0) => return Ok(0),
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if start.elapsed() > timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Read timeout",
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn create_session(&self, address: &str, port: Option<u16>) -> bool {
        let target_port = port.unwrap_or(self.port);
        self.log.save_data(&format!("Creating session with {}:{}", address, target_port));

        if address == self.host && target_port == self.port {
            self.log.save_data(&format!("Cannot connect to self ({}:{})", address, target_port));
            println!("Cannot connect to yourself!");
            return false;
        }

        if self.check_address(address) {
            self.log.save_data(&format!("Already connected to {}", address));
            println!("Already connected to {}", address);
            return true;
        }

        // Black list check
        if self.blacklist.contains(&address.to_string()) {
            self.log.save_data(&format!("{} is in blacklist", address));
            println!("{} is in blacklist", address);
            return false;
        }

        {
            let mut attempts = self.connection_attempts.lock().unwrap();
            if let Some(last_attempt) = attempts.get(address) {
                if last_attempt.elapsed() < Duration::from_secs(5) {
                    self.log.save_data(&format!("Connection attempt to {} is already in progress", address));
                    return false;
                }
            }
            attempts.insert(address.to_string(), std::time::Instant::now());
        }

        // Finding free slot
        for i in 0..self.max_clients {
            let socket_busy_guard = self.socket_busy.lock().unwrap();
            if !socket_busy_guard[i] {
                drop(socket_busy_guard);
                let result = self.connect_to_server(address, target_port, i);

                {
                    let mut attempts = self.connection_attempts.lock().unwrap();
                    attempts.remove(address);
                }

                return result;
            }
        }

        {
            let mut attempts = self.connection_attempts.lock().unwrap();
            attempts.remove(address);
        }

        self.log.save_data("All sockets are busy");
        false
    }

    fn connect_to_server(&self, address: &str, port: u16, idx: usize) -> bool {
        match TcpStream::connect((address, port)) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

                // 1. Send our public key
                let mut rng = OsRng;
                let private_key = match RsaPrivateKey::new(&mut rng, 512) {
                    Ok(key) => key,
                    Err(e) => {
                        self.log.save_data(&format!("Key generation error: {}", e));
                        return false;
                    }
                };

                let public_key = RsaPublicKey::from(&private_key);
                let pub_key_der = match public_key.to_pkcs1_der() {
                    Ok(der) => der,
                    Err(e) => {
                        self.log.save_data(&format!("Key serialization error: {}", e));
                        return false;
                    }
                };

                if let Err(e) = stream.write_all(pub_key_der.as_bytes()) {
                    self.log.save_data(&format!("Error sending key to {}:{}: {}", address, port, e));
                    return false;
                }

                // 2. Getting server key (public key by another side)
                let mut key_buf = [0u8; 1024];
                let key_size = match Self::read_with_timeout(&mut stream, &mut key_buf, Duration::from_secs(5)) {
                    Ok(size) => size,
                    Err(e) => {
                        self.log.save_data(&format!("Key read error from {}:{}: {}", address, port, e));
                        return false;
                    }
                };

                if key_size == 0 {
                    self.log.save_data(&format!("Empty key from {}:{}", address, port));
                    return false;
                }

                let server_key = match RsaPublicKey::from_pkcs1_der(&key_buf[..key_size]) {
                    Ok(key) => key,
                    Err(e) => {
                        self.log.save_data(&format!("Invalid server key from {}:{}: {}", address, port, e));
                        return false;
                    }
                };

                // 3. Save data
                {
                    let mut clients_ip_guard = self.clients_ip.lock().unwrap();
                    clients_ip_guard[idx] = address.to_string();

                    let mut socket_busy_guard = self.socket_busy.lock().unwrap();
                    socket_busy_guard[idx] = true;

                    let mut client_sockets_guard = self.client_sockets.lock().unwrap();
                    client_sockets_guard[idx] = Some(Arc::new(Mutex::new(stream.try_clone().unwrap())));

                    let mut keys_guard = self.keys.lock().unwrap();
                    keys_guard[idx] = Some(server_key); // Публичный ключ сервера для шифрования

                    let mut my_keys_guard = self.my_keys.lock().unwrap();
                    my_keys_guard[idx] = Some(private_key); // Наш приватный ключ для расшифровки
                }

                self.log.save_data(&format!("Session created with {}:{}", address, port));

                // Запускаем поток для прослушивания сообщений от сервера
                let running_clone = Arc::clone(&self.running);
                let clients_ip_clone = Arc::clone(&self.clients_ip);
                let incoming_requests_clone = Arc::clone(&self.incoming_requests);
                let socket_busy_clone = Arc::clone(&self.socket_busy);
                let my_keys_clone = Arc::clone(&self.my_keys);
                let log_clone = Arc::clone(&self.log);
                let address_clone = address.to_string();

                thread::spawn(move || {
                    Self::listen_to_server(
                        stream,
                        idx,
                        address_clone,
                        running_clone,
                        clients_ip_clone,
                        incoming_requests_clone,
                        socket_busy_clone,
                        my_keys_clone,
                        log_clone,
                    );
                });

                true
            }
            Err(e) => {
                self.log.save_data(&format!("Connection error to {}:{}: {}", address, port, e));
                self.reload_socket(idx);
                false
            }
        }
    }

    fn listen_to_server(
        mut stream: TcpStream,
        idx: usize,
        address: String,
        running: Arc<Mutex<bool>>,
        clients_ip: Arc<Mutex<Vec<String>>>,
        incoming_requests: Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>>,
        socket_busy: Arc<Mutex<Vec<bool>>>,
        my_keys: Arc<Mutex<Vec<Option<RsaPrivateKey>>>>,
        log: Arc<Log>,
    ) {
        if let Err(e) = stream.set_nonblocking(true) {
            log.save_data(&format!("Failed to set non-blocking for {}: {}", address, e));
        }

        let mut buf = [0u8; 2048];

        while *running.lock().unwrap() && socket_busy.lock().unwrap()[idx] {
            match stream.read(&mut buf) {
                Ok(0) => break, // Connection closed
                Ok(size) => {
                    let my_key_guard = my_keys.lock().unwrap();
                    if let Some(ref my_key) = my_key_guard[idx] {
                        match my_key.decrypt(Pkcs1v15Encrypt, &buf[..size]) {
                            Ok(decrypted) => {
                                let mut requests_guard = incoming_requests.lock().unwrap();
                                requests_guard
                                    .entry(address.clone())
                                    .or_insert_with(VecDeque::new)
                                    .push_back(decrypted);

                                log.save_data(&format!("Received message from {}", address));
                            }
                            Err(e) => {
                                log.save_data(&format!("Decrypt error from {}: {}", address, e));
                                break;
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    log.save_data(&format!("Read error from {}: {}", address, e));
                    break;
                }
            }
        }

        {
            let mut socket_busy_guard = socket_busy.lock().unwrap();
            socket_busy_guard[idx] = false;
        }

        {
            let mut clients_ip_guard = clients_ip.lock().unwrap();
            clients_ip_guard[idx] = String::new();
        }

        log.save_data(&format!("Stopped listening to {}", address));
    }

    fn reload_socket(&self, idx: usize) {
        {
            let mut client_sockets_guard = self.client_sockets.lock().unwrap();
            client_sockets_guard[idx] = None;
        }
        {
            let mut socket_busy_guard = self.socket_busy.lock().unwrap();
            socket_busy_guard[idx] = false;
        }
    }

    pub fn close_connection(&self, address: &str) {
        let idx = self.get_ind_by_address(address);
        if let Some(idx) = idx {
            Self::close_connection_internal(
                address,
                idx,
                Arc::clone(&self.clients_ip),
                Arc::clone(&self.incoming_requests),
                Arc::clone(&self.client_sockets),
                Arc::clone(&self.socket_busy),
                Arc::clone(&self.keys),
                Arc::clone(&self.my_keys),
                Arc::clone(&self.log),
            );
        }
    }

    fn close_connection_internal(
        address: &str,
        idx: usize,
        clients_ip: Arc<Mutex<Vec<String>>>,
        incoming_requests: Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>>,
        client_sockets: Arc<Mutex<Vec<Option<SharedTcpStream>>>>,
        socket_busy: Arc<Mutex<Vec<bool>>>,
        keys: Arc<Mutex<Vec<Option<RsaPublicKey>>>>,
        my_keys: Arc<Mutex<Vec<Option<RsaPrivateKey>>>>,
        log: Arc<Log>,
    ) {
        // Close socket
        {
            let mut client_sockets_guard = client_sockets.lock().unwrap();
            if let Some(socket) = &client_sockets_guard[idx] {
                if let Ok(mut sock) = socket.lock() {
                    let _ = sock.shutdown(std::net::Shutdown::Both);
                }
            }
            client_sockets_guard[idx] = None;
        }

        // Clean data
        {
            let mut clients_ip_guard = clients_ip.lock().unwrap();
            clients_ip_guard[idx] = String::new();
        }

        {
            let mut socket_busy_guard = socket_busy.lock().unwrap();
            socket_busy_guard[idx] = false;
        }

        {
            let mut keys_guard = keys.lock().unwrap();
            keys_guard[idx] = None;
        }

        {
            let mut my_keys_guard = my_keys.lock().unwrap();
            my_keys_guard[idx] = None;
        }

        {
            let mut requests_guard = incoming_requests.lock().unwrap();
            requests_guard.remove(address);
        }

        log.save_data(&format!("Closed connection with {}", address));
    }

    pub fn send(&self, address: &str, message: &str) -> bool {
        let idx = match self.get_ind_by_address(address) {
            Some(idx) => idx,
            None => {
                self.log.save_data(&format!("Cannot send to {}: not connected", address));
                return false;
            }
        };

        let key = {
            let keys_guard = self.keys.lock().unwrap();
            keys_guard[idx].clone()
        };

        match key {
            Some(key) => {
                let mut rng = OsRng;
                match key.encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes()) {
                    Ok(encrypted) => {
                        let socket = {
                            let client_sockets_guard = self.client_sockets.lock().unwrap();
                            client_sockets_guard[idx].clone()
                        };

                        match socket {
                            Some(socket) => {
                                if let Ok(mut sock) = socket.lock() {
                                    if sock.write_all(&encrypted).is_ok() {
                                        self.log.save_data(&format!("Send message to {}", address));
                                        return true;
                                    }
                                }
                            }
                            None => {
                                self.log.save_data(&format!("No socket for {}", address));
                                return false;
                            }
                        }
                    }
                    Err(e) => {
                        self.log.save_data(&format!("Encryption error for {}: {}", address, e));
                        return false;
                    }
                }
            }
            None => {
                self.log.save_data(&format!("Cannot send to {}: no key", address));
                return false;
            }
        }

        false
    }

    pub fn raw_send(&self, address: &str, message: &[u8]) -> bool {
        let idx = match self.get_ind_by_address(address) {
            Some(idx) => idx,
            None => return false,
        };

        let socket = {
            let client_sockets_guard = self.client_sockets.lock().unwrap();
            client_sockets_guard[idx].clone()
        };

        match socket {
            Some(socket) => {
                if let Ok(mut sock) = socket.lock() {
                    if sock.write_all(message).is_ok() {
                        self.log.save_data(&format!("Raw send message to {}", address));
                        return true;
                    }
                }
            }
            None => {
                self.log.save_data(&format!("No socket for {}", address));
                return false;
            }
        }

        false
    }

    fn get_ind_by_address(&self, address: &str) -> Option<usize> {
        let clients_ip_guard = self.clients_ip.lock().unwrap();
        for i in 0..self.max_clients {
            if clients_ip_guard[i] == address {
                return Some(i);
            }
        }
        None
    }

    pub fn get_request(&self, address: &str) -> Option<Vec<u8>> {
        let mut requests_guard = self.incoming_requests.lock().unwrap();
        if let Some(queue) = requests_guard.get_mut(address) {
            queue.pop_front()
        } else {
            None
        }
    }

    pub fn check_request(&self, address: &str) -> bool {
        let requests_guard = self.incoming_requests.lock().unwrap();
        if let Some(queue) = requests_guard.get(address) {
            !queue.is_empty()
        } else {
            false
        }
    }

    pub fn check_address(&self, address: &str) -> bool {
        let clients_ip_guard = self.clients_ip.lock().unwrap();
        clients_ip_guard.contains(&address.to_string())
    }

    pub fn kill_server(&self) -> Result<(), String> {
        *self.running.lock().unwrap() = false;

        thread::sleep(Duration::from_millis(500));

        let clients: Vec<String> = {
            let clients_ip_guard = self.clients_ip.lock().unwrap();
            clients_ip_guard.iter()
                .filter(|ip| !ip.is_empty())
                .cloned()
                .collect()
        };

        for client in clients {
            self.close_connection(&client);
        }

        self.log.kill_log();
        println!("Server killed");

        Ok(())
    }

    pub fn get_host_ip(&self) -> &str {
        &self.host
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_connected_clients(&self) -> Vec<String> {
        let clients_ip_guard = self.clients_ip.lock().unwrap();
        clients_ip_guard.iter()
            .filter(|ip| !ip.is_empty())
            .cloned()
            .collect()
    }

    pub fn connected_clients_count(&self) -> usize {
        let clients_ip_guard = self.clients_ip.lock().unwrap();
        clients_ip_guard.iter().filter(|ip| !ip.is_empty()).count()
    }
}
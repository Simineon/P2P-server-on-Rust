//! # P2P Client
//!
//! This is p2p client program, it creates p2p server and offers commands to manage.
//!
//! Author is Simineon - https://github.com/Simineon/
//!
//! GPL license cuz you can improve it and use in your projects(with GPL(Do not forgot GPL btw)). I
//! licensed it cuz its p2p server system by me.
//!
use crate::server::P2P;
use std::io::{self, Write};
use std::io::Result;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;

mod server;

struct MessageMonitor {
    p2p: Arc<P2P>,
    running: Arc<Mutex<bool>>,
}

impl MessageMonitor {
    fn new(p2p: Arc<P2P>) -> Self {
        MessageMonitor {
            p2p,
            running: Arc::new(Mutex::new(true)),
        }
    }

    fn start(&self) -> thread::JoinHandle<()> {
        let p2p_clone = Arc::clone(&self.p2p);
        let running_clone = Arc::clone(&self.running);

        thread::spawn(move || {
            while *running_clone.lock().unwrap() {
                let connected_addresses = p2p_clone.get_connected_clients();

                for addr in &connected_addresses {
                    if p2p_clone.check_request(addr) {
                        while let Some(msg) = p2p_clone.get_request(addr) {
                            let message = String::from_utf8_lossy(&msg);
                            println!("\n[SERVER_MESSAGE] New message from {}: {}", addr, message);
                            print!("[SERVER_PROMPT] > ");
                            let _ = io::stdout().flush();
                        }
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }
        })
    }

    fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }
}

fn print_server_info(port: u16, host_ip: &str) {
    println!("[SERVER_INFO] === P2P Server Started ===");
    println!("[SERVER_INFO] Port: {}", port);
    println!("[SERVER_INFO] Host IP: {}", host_ip);
    println!("[SERVER_INFO] Status: Ready");
    println!("[SERVER_INFO] ==========================");
}

fn main() -> Result<()> {
    println!("[SERVER_LOG] ===            P2P Chat Client              ===");
    println!("[SERVER_LOG] === Server system by Simineon, GPL license. ===");

    let port = if let Some(arg) = std::env::args().nth(1) {
        match arg.parse::<u16>() {
            Ok(p) => {
                println!("[SERVER_LOG] Using port from command line: {}", p);
                p
            }
            Err(_) => {
                println!("[SERVER_LOG] Invalid port argument, using default 5555");
                5555
            }
        }
    } else {
        println!("[SERVER_LOG] No port specified, using default 5555");
        5555
    };

    println!("[SERVER_LOG] Creating P2P server on port {}...", port);

    let p2p = match P2P::new(port, 10) {
        Ok(mut p2p) => {
            p2p.start();
            let host_ip = p2p.get_host_ip();
            print_server_info(port, &host_ip);
            Arc::new(p2p)
        }
        Err(e) => {
            eprintln!("[SERVER_ERROR] Failed to create P2P server: {}", e);
            return Ok(());
        }
    };

    let monitor = MessageMonitor::new(Arc::clone(&p2p));
    let monitor_thread = monitor.start();

    println!("\n[SERVER_HELP] Available commands:");
    println!("[SERVER_HELP]   connect <IP> [port]  - connect with another client");
    println!("[SERVER_HELP]   peers                - list connected clients");
    println!("[SERVER_HELP]   msg <address> <text> - send message");
    println!("[SERVER_HELP]   status               - show server status");
    println!("[SERVER_HELP]   refresh              - force refresh connections");
    println!("[SERVER_HELP]   help                 - show this help");
    println!("[SERVER_HELP]   exit                 - quit");
    println!("[SERVER_PROMPT] > ");

    let _ = io::stdout().flush();

    let mut sent_messages: Vec<String> = Vec::new();

    loop {
        let mut cmd = String::new();
        io::stdin().read_line(&mut cmd)?;

        let cmd = cmd.trim();
        if cmd.is_empty() {
            print!("[SERVER_PROMPT] > ");
            let _ = io::stdout().flush();
            continue;
        }

        println!("[SERVER_ECHO] > {}", cmd);

        match cmd.to_lowercase().as_str() {
            "exit" => {
                println!("[SERVER_LOG] Exiting...");
                break;
            }

            "peers" => {
                let connected = p2p.get_connected_clients();
                if connected.is_empty() {
                    println!("[SERVER_PEERS] No connections");
                } else {
                    println!("[SERVER_PEERS] Connected to: {}", connected.join(", "));
                }
                let connected_count = p2p.connected_clients_count();
                println!("[SERVER_PEERS] Active connections: {}", connected_count);
            }

            "status" => {
                let host_ip = p2p.get_host_ip();
                let connected_count = p2p.connected_clients_count();
                println!("[SERVER_STATUS] Server running on port {}", port);
                println!("[SERVER_STATUS] Host IP: {}", host_ip);
                println!("[SERVER_STATUS] Active connections: {}", connected_count);
                println!("[SERVER_STATUS] Server status: Active");
            }

            "myip" => {
                println!("[SERVER_INFO] Your IP: {}", p2p.get_host_ip());
            }

            "refresh" => {
                println!("[SERVER_LOG] Refreshing connections...");
                // Force connection check
                let connected = p2p.get_connected_clients();
                if connected.is_empty() {
                    println!("[SERVER_PEERS] No connections");
                } else {
                    println!("[SERVER_PEERS] Connected to: {}", connected.join(", "));
                }
            }

            cmd if cmd.starts_with("connect ") => {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[1];
                    let target_port = if parts.len() >= 3 {
                        match parts[2].parse::<u16>() {
                            Ok(p) => p,
                            Err(_) => {
                                println!("[SERVER_WARN] Invalid port, using default {}", port);
                                port
                            }
                        }
                    } else {
                        port
                    };

                    println!("[SERVER_LOG] Connecting to {}:{}...", ip, target_port);

                    thread::sleep(Duration::from_millis(100));

                    if p2p.create_session(ip, Some(target_port)) {
                        println!("[SERVER_SUCCESS] ✓ Connected to {}:{}", ip, target_port);
                        // Show updated peers list
                        let connected = p2p.get_connected_clients();
                        println!("[SERVER_PEERS] Connected to: {}", connected.join(", "));
                    } else {
                        println!("[SERVER_ERROR] ✗ Failed to connect to {}:{}", ip, target_port);
                    }
                } else {
                    println!("[SERVER_USAGE] Usage: connect <IP> [port]");
                }
            }

            cmd if cmd.starts_with("msg ") => {
                let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    let target = parts[1];
                    let message = parts[2];

                    // Check if the target is a valid address
                    let is_valid_address = if target.contains(':') {
                        target.parse::<SocketAddr>().is_ok()
                    } else {
                        // Assume it's just IP, check format
                        target.split('.').count() == 4 &&
                            target.split('.').all(|s| s.parse::<u8>().is_ok())
                    };

                    if !is_valid_address {
                        println!("[SERVER_ERROR] Invalid address format: {}", target);
                        continue;
                    }

                    // Check if we're connected to this address
                    let connected = p2p.get_connected_clients();
                    let is_connected = connected.iter().any(|addr| addr.contains(target));

                    if !is_connected {
                        println!("[SERVER_WARN] Not connected to {}. Use 'connect' first.", target);
                        continue;
                    }

                    sent_messages.push(format!("To {}: {}", target, message));

                    if p2p.send(target, message) {
                        println!("[SERVER_SUCCESS] ✓ Message sent to {}", target);
                    } else {
                        println!("[SERVER_ERROR] ✗ Failed to send to {}", target);
                    }
                } else {
                    println!("[SERVER_USAGE] Usage: msg <address> <text>");
                }
            }

            "msgs" => {
                if sent_messages.is_empty() {
                    println!("[SERVER_LOG] No sent messages yet");
                } else {
                    println!("\n[SERVER_LOG] Sent messages:");
                    println!("[SERVER_LOG] {}", "=".repeat(50));
                    for (i, msg) in sent_messages.iter().enumerate() {
                        println!("[SERVER_LOG] {}. {}", i + 1, msg);
                    }
                    println!("[SERVER_LOG] {}", "=".repeat(50));
                }
            }

            "help" => {
                println!("\n[SERVER_HELP] Available commands:");
                println!("[SERVER_HELP]   connect <IP> [port]  - connect to another peer");
                println!("[SERVER_HELP]   peers                - show connected peers");
                println!("[SERVER_HELP]   msg <IP> <text>      - send message");
                println!("[SERVER_HELP]   msgs                 - show sent messages history");
                println!("[SERVER_HELP]   status               - show server status");
                println!("[SERVER_HELP]   refresh              - refresh connections status");
                println!("[SERVER_HELP]   exit                 - exit program");
                println!("\n[SERVER_HELP] New messages appear automatically!");
            }

            _ => {
                println!("[SERVER_ERROR] Unknown command. Type 'help' for list of commands.");
            }
        }

        print!("[SERVER_PROMPT] > ");
        let _ = io::stdout().flush();
    }

    monitor.stop();
    let _ = monitor_thread.join();

    let _ = p2p.kill_server();

    println!("[SERVER_LOG] Server stopped.");
    Ok(())
}
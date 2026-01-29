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
                            println!("\nNew message from {}: {}", addr, message);
                            print!("> ");
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
    println!("=== P2P Server Started ===");
    println!("Port: {}", port);
    println!("Host IP: {}", host_ip);
    println!("Status: Ready");
    println!("==========================");
}

fn main() -> Result<()> {
    println!("===            P2P Chat Client              ===");
    println!("=== Server system by Simineon, GPL license. ===");

    let port = if let Some(arg) = std::env::args().nth(1) {
        match arg.parse::<u16>() {
            Ok(p) => {
                println!("Using port from command line: {}", p);
                p
            }
            Err(_) => {
                println!("Invalid port argument, using default 5555");
                5555
            }
        }
    } else {
        println!("No port specified, using default 5555");
        5555
    };

    println!("Creating P2P server on port {}...", port);

    let p2p = match P2P::new(port, 10) {
        Ok(mut p2p) => {
            p2p.start();
            let host_ip = p2p.get_host_ip();
            print_server_info(port, &host_ip);
            Arc::new(p2p)
        }
        Err(e) => {
            eprintln!("Failed to create P2P server: {}", e);
            return Ok(());
        }
    };

    let monitor = MessageMonitor::new(Arc::clone(&p2p));
    let monitor_thread = monitor.start();

    println!("\nAvailable commands:");
    println!("   connect <IP> [port]  - connect with another client");
    println!("   peers                - list connected clients");
    println!("   msg <address> <text> - send message");
    println!("   status               - show server status");
    println!("   refresh              - force refresh connections");
    println!("   help                 - show this help");
    println!("   exit                 - quit");
    print!("> ");

    let _ = io::stdout().flush();

    let mut sent_messages: Vec<String> = Vec::new();

    loop {
        let mut cmd = String::new();
        io::stdin().read_line(&mut cmd)?;

        let cmd = cmd.trim();
        if cmd.is_empty() {
            print!("> ");
            let _ = io::stdout().flush();
            continue;
        }
        
        match cmd.to_lowercase().as_str() {
            "exit" => {
                println!("Exiting...");
                break;
            }

            "peers" => {
                let connected = p2p.get_connected_clients();
                if connected.is_empty() {
                    println!("No connections");
                } else {
                    println!("Connected to: {}", connected.join(", "));
                }
                let connected_count = p2p.connected_clients_count();
                println!("Active connections: {}", connected_count);
            }

            "status" => {
                let host_ip = p2p.get_host_ip();
                let connected_count = p2p.connected_clients_count();
                println!("Server running on port {}", port);
                println!("Host IP: {}", host_ip);
                println!("Active connections: {}", connected_count);
                println!("Server status: Active");
            }

            "myip" => {
                println!("Your IP: {}", p2p.get_host_ip());
            }

            "refresh" => {
                println!("Refreshing connections...");
                // Force connection check
                let connected = p2p.get_connected_clients();
                if connected.is_empty() {
                    println!("No connections");
                } else {
                    println!("Connected to: {}", connected.join(", "));
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
                                println!("Invalid port, using default {}", port);
                                port
                            }
                        }
                    } else {
                        port
                    };

                    println!("Connecting to {}:{}...", ip, target_port);

                    thread::sleep(Duration::from_millis(100));

                    if p2p.create_session(ip, Some(target_port)) {
                        println!("[YES] Connected to {}:{}", ip, target_port);
                        // Show updated peers list
                        let connected = p2p.get_connected_clients();
                        println!("Connected to: {}", connected.join(", "));
                    } else {
                        println!("[NO] Failed to connect to {}:{}", ip, target_port);
                    }
                } else {
                    println!("Usage: connect <IP> [port]");
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
                        println!("Invalid address format: {}", target);
                        continue;
                    }

                    // Check if we're connected to this address
                    let connected = p2p.get_connected_clients();
                    let is_connected = connected.iter().any(|addr| addr.contains(target));

                    if !is_connected {
                        println!("Not connected to {}. Use 'connect' first.", target);
                        continue;
                    }

                    sent_messages.push(format!("To {}: {}", target, message));

                    if p2p.send(target, message) {
                        println!("[YES] Message sent to {}", target);
                    } else {
                        println!("[NO] Failed to send to {}", target);
                    }
                } else {
                    println!("Usage: msg <address> <text>");
                }
            }

            "msgs" => {
                if sent_messages.is_empty() {
                    println!("No sent messages yet");
                } else {
                    println!("\nSent messages:");
                    println!("{}", "=".repeat(50));
                    for (i, msg) in sent_messages.iter().enumerate() {
                        println!("{}. {}", i + 1, msg);
                    }
                    println!("{}", "=".repeat(50));
                }
            }

            "help" => {
                println!("\nAvailable commands:");
                println!("   connect <IP> [port]  - connect to another peer");
                println!("   peers                - show connected peers");
                println!("   msg <IP> <text>      - send message");
                println!("   msgs                 - show sent messages history");
                println!("   status               - show server status");
                println!("   refresh              - refresh connections status");
                println!("   exit                 - exit program");
                println!("\nNew messages appear automatically!");
            }

            _ => {
                println!("Unknown command. Type 'help' for list of commands.");
            }
        }

        print!("> ");
        let _ = io::stdout().flush();
    }

    monitor.stop();
    let _ = monitor_thread.join();

    let _ = p2p.kill_server();

    println!("Server stopped.");
    Ok(())
}
//! # P2P Client
//!
//! This is p2p client program, it creates p2p server and offers commands to manage.
//!
//! Author is Simineon - https://github.com/Simineon/
//!
//! GPL license cuz you can improve it and use in your projects(with GPL(Do not forgot GPL btw)). I
//! licensed it cuz its p2p server system by me.
//!
//! Distribute! Improve! Create! Fight! Don't put up with proprietary software!
use crate::server::P2P;
use std::io::{self, Write};
use std::io::Result;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};

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
                            println!("\n[New message from {}]: {}", addr, message);
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

fn main() -> Result<()> {
    println!("===            P2P Chat Client              ===");
    println!("=== Server system by Simineon, GPL license. ===");
    println!("=== Distribute! Improve! Create! Fight!     ===");
    println!("=== Don't put up with proprietary software! ===");
    println!("Enter port (default 5555): ");

    let mut port_input = String::new();
    io::stdin().read_line(&mut port_input)?;

    let port_input = port_input.trim();
    let port: u16 = if port_input.is_empty() {
        5555
    } else {
        match port_input.parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Invalid port, using default 5555");
                5555
            }
        }
    };

    println!("Creating P2P server on port {}...", port);

    let p2p = match P2P::new(port, 10) {
        Ok(mut p2p) => {
            p2p.start();
            println!("✓ P2P server created successfully on {}:{}", p2p.get_host_ip(), port);
            Arc::new(p2p)
        }
        Err(e) => {
            eprintln!("✗ Failed to create P2P server: {}", e);
            return Ok(());
        }
    };

    let monitor = MessageMonitor::new(Arc::clone(&p2p));
    let monitor_thread = monitor.start();

    println!("\nCommands:");
    println!("  connect <IP> [port]  - connect with another client");
    println!("  peers                - list of connected clients");
    println!("  msg <address> <text> - send message");
    println!("  exit                 - exit");
    println!("  msgs                 - (to be implemented)");
    println!("  refresh              - force refresh connections");
    println!("  help                 - show this help");
    println!("  exit                 - quit");
    println!("\nShare your IP and port with others to connect.");
    println!("New messages will appear automatically!\n");

    let mut sent_messages: Vec<String> = Vec::new();

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut cmd = String::new();
        io::stdin().read_line(&mut cmd)?;

        let cmd = cmd.trim();
        if cmd.is_empty() {
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
                        println!("✓ Connected to {}:{}", ip, target_port);
                    } else {
                        println!("✗ Failed to connect to {}:{}", ip, target_port);
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

                    if !p2p.check_address(target) {
                        println!("Not connected to {}. Use 'connect' first.", target);
                        continue;
                    }

                    sent_messages.push(format!("To {}: {}", target, message));

                    if p2p.send(target, message) {
                        println!("✓ Sent to {}", target);
                    } else {
                        println!("✗ Failed to send to {}", target);
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

            "refresh" => {
                let connected_count = p2p.connected_clients_count();
                println!("Active connections: {}", connected_count);
            }

            "help" => {
                println!("\nAvailable commands:");
                println!("  connect <IP> [port]  - connect to another peer");
                println!("  peers                - show connected peers");
                println!("  msg <IP> <text>      - send message");
                println!("  msgs                 - show sent messages history");
                println!("  refresh              - refresh connections status");
                println!("  exit                 - exit program");
                println!("\nNew messages appear automatically!");
            }

            _ => {
                println!("Unknown command. Type 'help' for list of commands.");
            }
        }
    }

    monitor.stop();
    let _ = monitor_thread.join();

    let _ = p2p.kill_server();

    println!("Server stopped.");
    Ok(())
}
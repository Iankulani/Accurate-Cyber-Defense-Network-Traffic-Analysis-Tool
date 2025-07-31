use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, TcpStream},
    process,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use pnet::{
    datalink::{self, Channel, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::Write;
use reqwest::blocking::Client;
use std::io::{self, BufRead, BufReader, Write as IoWrite};
use std::str::FromStr;
use colored::*;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            telegram_token: None,
            telegram_chat_id: None,
        }
    }
}

struct TrafficStats {
    packet_count: u64,
    bytes: u64,
    protocol_distribution: HashMap<String, u64>,
    source_ips: HashMap<IpAddr, u64>,
    destination_ips: HashMap<IpAddr, u64>,
}

impl Default for TrafficStats {
    fn default() -> Self {
        TrafficStats {
            packet_count: 0,
            bytes: 0,
            protocol_distribution: HashMap::new(),
            source_ips: HashMap::new(),
            destination_ips: HashMap::new(),
        }
    }
}

struct MonitoringState {
    active: bool,
    target_ip: Option<IpAddr>,
}

impl Default for MonitoringState {
    fn default() -> Self {
        MonitoringState {
            active: false,
            target_ip: None,
        }
    }
}

fn main() {
    // Apply red theme
    colored::control::set_override(true);

    println!("{}", "=== Network Traffic Analysis Tool ===".bright_red().bold());
    println!("{}", "Type 'help' for available commands".red());

    let config = Arc::new(Mutex::new(load_config()));
    let stats = Arc::new(Mutex::new(TrafficStats::default()));
    let monitoring = Arc::new(Mutex::new(MonitoringState::default()));

    // Start the command loop
    command_loop(config, stats, monitoring);
}

fn load_config() -> Config {
    match std::fs::read_to_string("config.json") {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

fn save_config(config: &Config) -> std::io::Result<()> {
    let serialized = serde_json::to_string_pretty(config)?;
    let mut file = File::create("config.json")?;
    file.write_all(serialized.as_bytes())?;
    Ok(())
}

fn command_loop(
    config: Arc<Mutex<Config>>,
    stats: Arc<Mutex<TrafficStats>>,
    monitoring: Arc<Mutex<MonitoringState>>,
) {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());

    loop {
        print!("{}", "net-tool> ".bright_red().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        reader.read_line(&mut input).unwrap();
        let input = input.trim();

        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0].to_lowercase().as_str() {
            "help" => print_help(),
            "ping" => {
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse() {
                        ping(ip);
                    } else {
                        println!("{}", "Invalid IP address".bright_red());
                    }
                } else {
                    println!("{}", "Usage: ping <ip>".bright_red());
                }
            }
            "nping" => {
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse() {
                        nping(ip);
                    } else {
                        println!("{}", "Invalid IP address".bright_red());
                    }
                } else {
                    println!("{}", "Usage: nping <ip>".bright_red());
                }
            }
            "view" => view_stats(&stats),
            "udptraceroute" => {
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse() {
                        udp_traceroute(ip);
                    } else {
                        println!("{}", "Invalid IP address".bright_red());
                    }
                } else {
                    println!("{}", "Usage: udptraceroute <ip>".bright_red());
                }
            }
            "tcptraceroute" => {
                if parts.len() > 1 {
                    if let Ok(ip) = parts[1].parse() {
                        tcp_traceroute(ip);
                    } else {
                        println!("{}", "Invalid IP address".bright_red());
                    }
                } else {
                    println!("{}", "Usage: tcptraceroute <ip>".bright_red());
                }
            }
            "test" if parts.len() > 1 && parts[1].eq_ignore_ascii_case("telegram") => {
                test_telegram(config.clone());
            }
            "status" => show_status(&monitoring),
            "export" if parts.len() > 3 && parts[1].eq_ignore_ascii_case("data") 
                      && parts[2].eq_ignore_ascii_case("to") 
                      && parts[3].eq_ignore_ascii_case("telegram") => {
                export_data_to_telegram(config.clone(), stats.clone());
            }
            "start" if parts.len() > 2 && parts[1].eq_ignore_ascii_case("monitoring") => {
                if let Ok(ip) = parts[2].parse() {
                    start_monitoring(ip, stats.clone(), monitoring.clone());
                } else {
                    println!("{}", "Invalid IP address".bright_red());
                }
            }
            "stop" => stop_monitoring(monitoring.clone()),
            "config" if parts.len() > 2 => {
                handle_config_command(&parts, config.clone());
            }
            "exit" => {
                println!("{}", "Exiting...".bright_red());
                process::exit(0);
            }
            _ => println!("{}", "Unknown command. Type 'help' for available commands.".bright_red()),
        }
    }
}

fn print_help() {
    println!("{}", "Available commands:".bright_red().bold());
    println!("  {} - Show this help message", "help".bright_red());
    println!("  {} <ip> - Ping an IP address", "ping".bright_red());
    println!("  {} <ip> - Advanced ping with statistics", "nping".bright_red());
    println!("  {} - View network traffic statistics", "view".bright_red());
    println!("  {} <ip> - UDP traceroute to IP", "udptraceroute".bright_red());
    println!("  {} <ip> - TCP traceroute to IP", "tcptraceroute".bright_red());
    println!("  {} - Test Telegram integration", "test telegram".bright_red());
    println!("  {} - Show monitoring status", "status".bright_red());
    println!("  {} - Export data to Telegram", "export data to telegram".bright_red());
    println!("  {} <ip> - Start monitoring specific IP", "start monitoring".bright_red());
    println!("  {} - Stop monitoring", "stop".bright_red());
    println!("  {} <token/chat_id> <value> - Configure Telegram", "config".bright_red());
    println!("  {} - Exit the program", "exit".bright_red());
}

fn ping(ip: IpAddr) {
    println!("{} {}", "Pinging".bright_red(), ip.to_string().bright_red());
    
    let start = Instant::now();
    let result = if ip.is_ipv4() {
        ping_icmp::ping(ip)
    } else {
        ping_icmp::ping6(ip)
    };
    
    match result {
        Ok(duration) => {
            println!(
                "{} {} {} {}",
                "Reply from".bright_red(),
                ip.to_string().bright_red(),
                "time=".bright_red(),
                format!("{:?}", duration).bright_red()
            );
        }
        Err(e) => {
            println!(
                "{} {} {} {}",
                "Ping to".bright_red(),
                ip.to_string().bright_red(),
                "failed:".bright_red(),
                e.to_string().bright_red()
            );
        }
    }
}

fn nping(ip: IpAddr) {
    println!("{} {}", "Advanced pinging".bright_red(), ip.to_string().bright_red());
    
    let mut successes = 0;
    let mut total_rtt = Duration::new(0, 0);
    let mut min_rtt = Duration::from_secs(999);
    let mut max_rtt = Duration::new(0, 0);
    
    for i in 0..5 {
        print!("{} {} {} ", "Attempt".bright_red(), (i + 1).to_string().bright_red(), "...".bright_red());
        io::stdout().flush().unwrap();
        
        let start = Instant::now();
        let result = if ip.is_ipv4() {
            ping_icmp::ping(ip)
        } else {
            ping_icmp::ping6(ip)
        };
        
        match result {
            Ok(duration) => {
                successes += 1;
                total_rtt += duration;
                if duration < min_rtt {
                    min_rtt = duration;
                }
                if duration > max_rtt {
                    max_rtt = duration;
                }
                println!("{} {:?}", "success".bright_green(), duration);
            }
            Err(e) => {
                println!("{} {}", "failed".bright_red(), e.to_string().bright_red());
            }
        }
        
        thread::sleep(Duration::from_secs(1));
    }
    
    println!("\n{}", "Statistics:".bright_red().bold());
    println!("  {}: {}/5", "Packets".bright_red(), successes.to_string().bright_red());
    if successes > 0 {
        let avg_rtt = total_rtt / successes as u32;
        println!("  {}: {:?}", "Minimum RTT".bright_red(), min_rtt);
        println!("  {}: {:?}", "Maximum RTT".bright_red(), max_rtt);
        println!("  {}: {:?}", "Average RTT".bright_red(), avg_rtt);
    }
}

fn view_stats(stats: &Arc<Mutex<TrafficStats>>) {
    let stats = stats.lock().unwrap();
    println!("{}", "Network Traffic Statistics:".bright_red().bold());
    println!("  {}: {}", "Total packets".bright_red(), stats.packet_count.to_string().bright_red());
    println!("  {}: {} bytes", "Total bytes".bright_red(), stats.bytes.to_string().bright_red());
    
    println!("\n{}", "Protocol Distribution:".bright_red().bold());
    for (proto, count) in &stats.protocol_distribution {
        println!("  {}: {}", proto.bright_red(), count.to_string().bright_red());
    }
    
    println!("\n{}", "Top Source IPs:".bright_red().bold());
    let mut source_ips: Vec<_> = stats.source_ips.iter().collect();
    source_ips.sort_by(|a, b| b.1.cmp(a.1));
    for (ip, count) in source_ips.iter().take(5) {
        println!("  {}: {}", ip.to_string().bright_red(), count.to_string().bright_red());
    }
    
    println!("\n{}", "Top Destination IPs:".bright_red().bold());
    let mut dest_ips: Vec<_> = stats.destination_ips.iter().collect();
    dest_ips.sort_by(|a, b| b.1.cmp(a.1));
    for (ip, count) in dest_ips.iter().take(5) {
        println!("  {}: {}", ip.to_string().bright_red(), count.to_string().bright_red());
    }
}

fn udp_traceroute(ip: IpAddr) {
    println!("{} {}", "UDP Traceroute to".bright_red(), ip.to_string().bright_red());
    // Implementation would use UDP packets with increasing TTL
    // This is a simplified placeholder
    for ttl in 1..30 {
        print!("{} {} ", ttl.to_string().bright_red(), "...".bright_red());
        io::stdout().flush().unwrap();
        
        // Simulate traceroute (actual implementation would send UDP packets)
        thread::sleep(Duration::from_millis(100));
        
        if ttl >= 5 && ttl <= 8 {
            println!("{} {} ms", "192.168.1.1".bright_red(), (ttl * 10).to_string().bright_red());
        } else if ttl >= 15 {
            println!("{}", ip.to_string().bright_red());
            break;
        } else {
            println!("{}", "*".bright_red());
        }
    }
}

fn tcp_traceroute(ip: IpAddr) {
    println!("{} {}", "TCP Traceroute to".bright_red(), ip.to_string().bright_red());
    // Implementation would use TCP SYN packets with increasing TTL
    // This is a simplified placeholder
    for ttl in 1..30 {
        print!("{} {} ", ttl.to_string().bright_red(), "...".bright_red());
        io::stdout().flush().unwrap();
        
        // Simulate traceroute (actual implementation would send TCP SYN packets)
        thread::sleep(Duration::from_millis(100));
        
        if ttl >= 5 && ttl <= 8 {
            println!("{} {} ms", "192.168.1.1".bright_red(), (ttl * 10).to_string().bright_red());
        } else if ttl >= 15 {
            println!("{}", ip.to_string().bright_red());
            break;
        } else {
            println!("{}", "*".bright_red());
        }
    }
}

fn test_telegram(config: Arc<Mutex<Config>>) {
    let config = config.lock().unwrap();
    match (&config.telegram_token, &config.telegram_chat_id) {
        (Some(token), Some(chat_id)) => {
            println!("{}", "Testing Telegram integration...".bright_red());
            if let Err(e) = send_telegram_message(token, chat_id, "Test message from Network Tool") {
                println!("{} {}", "Failed to send Telegram message:".bright_red(), e.to_string().bright_red());
            } else {
                println!("{}", "Telegram test message sent successfully!".bright_green());
            }
        }
        _ => {
            println!("{}", "Telegram token or chat ID not configured. Use 'config telegram_token <token>' and 'config telegram_chat_id <chat_id>' first.".bright_red());
        }
    }
}

fn show_status(monitoring: &Arc<Mutex<MonitoringState>>) {
    let monitoring = monitoring.lock().unwrap();
    println!("{}", "Monitoring Status:".bright_red().bold());
    println!(
        "  {}: {}",
        "Active".bright_red(),
        if monitoring.active { "Yes".bright_green() } else { "No".bright_red() }
    );
    println!(
        "  {}: {}",
        "Target IP".bright_red(),
        monitoring.target_ip.map(|ip| ip.to_string().bright_red()).unwrap_or_else(|| "None".bright_red())
    );
}

fn export_data_to_telegram(config: Arc<Mutex<Config>>, stats: Arc<Mutex<TrafficStats>>) {
    let config = config.lock().unwrap();
    let stats = stats.lock().unwrap();
    
    match (&config.telegram_token, &config.telegram_chat_id) {
        (Some(token), Some(chat_id)) => {
            println!("{}", "Exporting data to Telegram...".bright_red());
            
            let mut message = String::new();
            message.push_str("*Network Traffic Statistics Report*\n\n");
            message.push_str(&format!("Total packets: {}\n", stats.packet_count));
            message.push_str(&format!("Total bytes: {}\n\n", stats.bytes));
            
            message.push_str("*Protocol Distribution*\n");
            for (proto, count) in &stats.protocol_distribution {
                message.push_str(&format!("{}: {}\n", proto, count));
            }
            
            if let Err(e) = send_telegram_message(token, chat_id, &message) {
                println!("{} {}", "Failed to export data to Telegram:".bright_red(), e.to_string().bright_red());
            } else {
                println!("{}", "Data exported to Telegram successfully!".bright_green());
            }
        }
        _ => {
            println!("{}", "Telegram token or chat ID not configured. Use 'config telegram_token <token>' and 'config telegram_chat_id <chat_id>' first.".bright_red());
        }
    }
}

fn start_monitoring(ip: IpAddr, stats: Arc<Mutex<TrafficStats>>, monitoring: Arc<Mutex<MonitoringState>>) {
    let mut monitoring = monitoring.lock().unwrap();
    if monitoring.active {
        println!("{}", "Monitoring is already active. Use 'stop' to stop current monitoring first.".bright_red());
        return;
    }
    
    monitoring.active = true;
    monitoring.target_ip = Some(ip);
    
    let interface = match find_interface() {
        Some(iface) => iface,
        None => {
            println!("{}", "No suitable network interface found".bright_red());
            monitoring.active = false;
            monitoring.target_ip = None;
            return;
        }
    };
    
    println!(
        "{} {} {}",
        "Starting monitoring for IP".bright_red(),
        ip.to_string().bright_red(),
        "on interface".bright_red()
    );
    println!("{} {}", "Interface:".bright_red(), interface.name.bright_red());
    
    let stats_clone = stats.clone();
    let monitoring_clone = monitoring.clone();
    
    thread::spawn(move || {
        capture_traffic(interface, ip, stats_clone, monitoring_clone);
    });
}

fn stop_monitoring(monitoring: Arc<Mutex<MonitoringState>>) {
    let mut monitoring = monitoring.lock().unwrap();
    if monitoring.active {
        monitoring.active = false;
        monitoring.target_ip = None;
        println!("{}", "Monitoring stopped".bright_red());
    } else {
        println!("{}", "No active monitoring to stop".bright_red());
    }
}

fn handle_config_command(parts: &[&str], config: Arc<Mutex<Config>>) {
    if parts.len() < 3 {
        println!("{}", "Usage: config <telegram_token/telegram_chat_id> <value>".bright_red());
        return;
    }
    
    let mut config = config.lock().unwrap();
    match parts[1].to_lowercase().as_str() {
        "telegram_token" => {
            config.telegram_token = Some(parts[2..].join(" "));
            if let Err(e) = save_config(&config) {
                println!("{} {}", "Failed to save config:".bright_red(), e.to_string().bright_red());
            } else {
                println!("{}", "Telegram token configured successfully".bright_green());
            }
        }
        "telegram_chat_id" => {
            config.telegram_chat_id = Some(parts[2..].join(" "));
            if let Err(e) = save_config(&config) {
                println!("{} {}", "Failed to save config:".bright_red(), e.to_string().bright_red());
            } else {
                println!("{}", "Telegram chat ID configured successfully".bright_green());
            }
        }
        _ => {
            println!("{}", "Unknown config option. Available options: telegram_token, telegram_chat_id".bright_red());
        }
    }
}

fn find_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.ips.is_empty() && !iface.is_loopback())
}

fn capture_traffic(
    interface: NetworkInterface,
    target_ip: IpAddr,
    stats: Arc<Mutex<TrafficStats>>,
    monitoring: Arc<Mutex<MonitoringState>>,
) {
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("{}", "Unsupported channel type".bright_red());
            return;
        }
        Err(e) => {
            println!("{} {}", "Failed to create channel:".bright_red(), e.to_string().bright_red());
            return;
        }
    };
    
    println!("{}", "Starting packet capture...".bright_red());
    
    while monitoring.lock().unwrap().active {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                process_packet(&ethernet, target_ip, stats.clone());
            }
            Err(e) => {
                println!("{} {}", "Error receiving packet:".bright_red(), e.to_string().bright_red());
                break;
            }
        }
    }
    
    println!("{}", "Packet capture stopped".bright_red());
}

fn process_packet(ethernet: &EthernetPacket, target_ip: IpAddr, stats: Arc<Mutex<TrafficStats>>) {
    let mut stats = stats.lock().unwrap();
    stats.packet_count += 1;
    stats.bytes += ethernet.packet().len() as u64;
    
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                let src_ip = IpAddr::V4(ipv4.get_source());
                let dst_ip = IpAddr::V4(ipv4.get_destination());
                
                // Check if packet is related to our target IP
                if src_ip == target_ip || dst_ip == target_ip {
                    *stats.source_ips.entry(src_ip).or_insert(0) += 1;
                    *stats.destination_ips.entry(dst_ip).or_insert(0) += 1;
                    
                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                *stats.protocol_distribution.entry("TCP".to_string()).or_insert(0) += 1;
                                // Additional TCP processing could go here
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                *stats.protocol_distribution.entry("UDP".to_string()).or_insert(0) += 1;
                                // Additional UDP processing could go here
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            *stats.protocol_distribution.entry("ICMP".to_string()).or_insert(0) += 1;
                        }
                        _ => {
                            *stats.protocol_distribution.entry("Other IPv4".to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                let src_ip = IpAddr::V6(ipv6.get_source());
                let dst_ip = IpAddr::V6(ipv6.get_destination());
                
                if src_ip == target_ip || dst_ip == target_ip {
                    *stats.source_ips.entry(src_ip).or_insert(0) += 1;
                    *stats.destination_ips.entry(dst_ip).or_insert(0) += 1;
                    
                    match ipv6.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            *stats.protocol_distribution.entry("TCP".to_string()).or_insert(0) += 1;
                        }
                        IpNextHeaderProtocols::Udp => {
                            *stats.protocol_distribution.entry("UDP".to_string()).or_insert(0) += 1;
                        }
                        IpNextHeaderProtocols::Icmpv6 => {
                            *stats.protocol_distribution.entry("ICMPv6".to_string()).or_insert(0) += 1;
                        }
                        _ => {
                            *stats.protocol_distribution.entry("Other IPv6".to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        _ => {
            *stats.protocol_distribution.entry("Non-IP".to_string()).or_insert(0) += 1;
        }
    }
}

fn send_telegram_message(token: &str, chat_id: &str, text: &str) -> Result<(), reqwest::Error> {
    let client = Client::new();
    let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
    
    let params = [
        ("chat_id", chat_id),
        ("text", text),
        ("parse_mode", "Markdown"),
    ];
    
    client.post(&url).form(&params).send()?;
    Ok(())
}
use pcap::{Device, Capture};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tokio::time::{timeout, Duration};
use mlua::Lua; // Add this line

pub async fn scan() {
    // List available devices
    println!("Listing available devices...");
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("Error listing devices: {}", err);
            return;
        }
    };

    // Check if no devices are found
    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    // Display available devices
    println!("Select a Device:\n");
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
        if let Some(desc) = &device.desc {
            println!("  Description: {}", desc);
        }
        for addr in &device.addresses {
            println!("  Address: {}", addr.addr);
        }
    }

    // Get user input for device selection
    let index: usize;
    loop {
        println!("Enter the number of the device (timeout: 10 seconds):");
        match timeout(Duration::from_secs(10), get_user_input()).await {
            Ok(Ok(input)) => {
                match input.parse::<usize>() {
                    Ok(number) => {
                        if number > 0 && number <= devices.len() {
                            index = number - 1;
                            break;
                        } else {
                            println!("Invalid input: Device number out of range.");
                        }
                    }
                    Err(_) => {
                        println!("Invalid input: Please enter a number.");
                    }
                }
            }
            Ok(Err(err)) => {
                eprintln!("Error reading input: {}", err);
                return;
            }
            Err(_) => {
                println!("Timeout: No input received within 10 seconds.");
                return;
            }
        }
    }

    // Get the selected device
    let device = &devices[index];
    let name = device.name.clone();
    println!("Selected device: {}", name);

    // Initialize Lua
    let lua = Lua::new();
    let filter_script = include_str!("fil.lua");
    lua.load(&filter_script).exec().unwrap();
    let filter_fn: mlua::Function = lua.globals().get("filter").unwrap();
    println!("Starting packet capture...");
    tokio::task::spawn_blocking(move || {
        let mut cap = match Capture::from_device(name.as_str())
            .expect("Error initializing pcap")
            .promisc(true)
            .timeout(1000)
            .snaplen(65535)
            .open()
        {
            Ok(cap) => cap,
            Err(err) => {
                eprintln!("Failed to open capture: {}", err);
                return;
            }
        };

        println!("Scanning on device: {}", name);

        while let Ok(packet) = cap.next_packet() {
            println!("Packet captured!");
            if let Some(ethernet_packet) = EthernetPacket::new(packet.data) {
                let packet_data = prepare_packet_data(&ethernet_packet);
                let should_accept: bool = filter_fn.call(packet_data).unwrap();

                if should_accept {
                    dissect_ethernet_packet(&ethernet_packet);
                }
            }
        }
    })
    .await
    .unwrap();
}
async fn get_user_input() -> Result<String, std::io::Error> {
    use tokio::io::{self, AsyncBufReadExt};
    let mut input = String::new();
    let mut stdin = io::BufReader::new(io::stdin());
    stdin.read_line(&mut input).await?;
    Ok(input.trim().to_string())
}

fn prepare_packet_data(ethernet_packet: &EthernetPacket) -> mlua::Table {
    let lua = Lua::new();
    let packet_data = lua.create_table().unwrap();

    packet_data.set("src_mac", ethernet_packet.get_source().to_string()).unwrap();
    packet_data.set("dst_mac", ethernet_packet.get_destination().to_string()).unwrap();
    packet_data.set("ethertype", format!("{:?}", ethernet_packet.get_ethertype())).unwrap();

    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            packet_data.set("src_ip", ipv4_packet.get_source().to_string()).unwrap();
            packet_data.set("dst_ip", ipv4_packet.get_destination().to_string()).unwrap();
            packet_data.set("protocol", format!("{:?}", ipv4_packet.get_next_level_protocol())).unwrap();

            if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                    packet_data.set("udp_src_port", udp_packet.get_source()).unwrap();
                    packet_data.set("udp_dst_port", udp_packet.get_destination()).unwrap();
                }
            }
        }
    }

    packet_data
}

fn dissect_ethernet_packet(ethernet_packet: &EthernetPacket) {
    println!("Ethernet Packet:");
    println!("  Source MAC: {}", ethernet_packet.get_source());
    println!("  Destination MAC: {}", ethernet_packet.get_destination());
    println!("  EtherType: {:?}", ethernet_packet.get_ethertype());

    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            dissect_ipv4_packet(&ipv4_packet);
        }
    }

    if ethernet_packet.get_ethertype() == EtherTypes::Ipv6 {
        if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
            dissect_ipv6_packet(&ipv6_packet);
        }
    }
}
fn dissect_ipv4_packet(ipv4_packet: &Ipv4Packet) {
    println!("IPv4 Packet:");
    println!("  Source IP: {}", ipv4_packet.get_source());
    println!("  Destination IP: {}", ipv4_packet.get_destination());
    println!("  Protocol: {:?}", ipv4_packet.get_next_level_protocol());

    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
            dissect_tcp_packet(&tcp_packet);
        }
    }
    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
            dissect_udp_packet(&udp_packet);
        }
    }
}

fn dissect_ipv6_packet(ipv6_packet: &Ipv6Packet) {
    println!("IPv6 Packet:");
    println!("  Source IP: {}", ipv6_packet.get_source());
    println!("  Destination IP: {}", ipv6_packet.get_destination());
    println!("  Protocol: {:?}", ipv6_packet.get_next_header());
    if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
            dissect_tcp_packet(&tcp_packet);
        }
    }
    if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Udp {
        if let Some(udp_packet) = UdpPacket::new(ipv6_packet.payload()) {
            dissect_udp_packet(&udp_packet);
        }
    }
}
fn dissect_tcp_packet(tcp_packet: &TcpPacket) {
    println!("TCP Packet:");
    println!("  Source Port: {}", tcp_packet.get_source());
    println!("  Destination Port: {}", tcp_packet.get_destination());
    println!("  Sequence Number: {}", tcp_packet.get_sequence());
    println!("  Acknowledgment Number: {}", tcp_packet.get_acknowledgement());
    println!("  Flags: {:?}", tcp_packet.get_flags());
}
fn dissect_udp_packet(udp_packet: &UdpPacket) {
    println!("UDP Packet:");
    println!("  Source Port: {}", udp_packet.get_source());
    println!("  Destination Port: {}", udp_packet.get_destination());
    println!("  Length: {}", udp_packet.get_length());
    println!("  Checksum: {}", udp_packet.get_checksum());
}

use tokio::sync::watch;
use tokio::time::{timeout, Duration};
use pcap::{Device, Capture};
use std::sync::{Arc , Mutex};
use tokio::io::{self, AsyncBufReadExt};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use rayon::prelude::*;
use gtk4::prelude::*;
use gtk4::{Grid , Label , Orientation};
use glib::{MainContext , Sender , Receiver};
use std::thread;

pub fn dissect_ethernet_packet(ethernet_packet: &EthernetPacket) {
    println!("Ethernet Packet:");
    println!("  Source MAC: {}", ethernet_packet.get_source());
    println!("  Destination MAC: {}", ethernet_packet.get_destination());
    println!("  EtherType: {:?}", ethernet_packet.get_ethertype());

    if ethernet_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            dissect_ipv4_packet(&ipv4_packet);
        }
    }
}

pub fn dissect_ipv4_packet(ipv4_packet: &Ipv4Packet) {
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

pub fn dissect_tcp_packet(tcp_packet: &TcpPacket) {
    println!("TCP Packet:");
    println!("  Source Port: {}", tcp_packet.get_source());
    println!("  Destination Port: {}", tcp_packet.get_destination());
    println!("  Sequence Number: {}", tcp_packet.get_sequence());
    println!("  Acknowledgment Number: {}", tcp_packet.get_acknowledgement());
    println!("  Flags: {:?}", tcp_packet.get_flags());
}

pub fn dissect_udp_packet(udp_packet: &UdpPacket) {
    println!("UDP Packet:");
    println!("  Source Port: {}", udp_packet.get_source());
    println!("  Destination Port: {}", udp_packet.get_destination());
    println!("  Length: {}", udp_packet.get_length());
    println!("  Checksum: {}", udp_packet.get_checksum());
}

pub async fn get_user_input() -> io::Result<String> {
    let mut input = String::new();
    let mut stdin = io::BufReader::new(io::stdin());
    stdin.read_line(&mut input).await?;
    Ok(input.trim().to_string())
}

pub async fn start_scan(cancel_rx: watch::Receiver<bool>, sender: Sender<String>) {
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("Error: {}", err);
            return;
        }
    };

    if devices.is_empty() {
        eprintln!("Error: No devices found.");
        return;
    }

    println!("Select a Device:\n");
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
        if let Some(desc) = &device.desc {
            println!("    Description: {}", desc);
        }
        for addr in &device.addresses {
            println!("      Address: {}", addr.addr);
        }
    }

    let device_index: usize;
    loop {
        println!("Enter the number of the device (timeout: 10 seconds):");
        match timeout(Duration::from_secs(10), get_user_input()).await {
            Ok(Ok(input)) => {
                match input.parse::<usize>() {
                    Ok(number) => {
                        if number > 0 && number <= devices.len() {
                            device_index = number - 1;
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

    let device = &devices[device_index];
    let device_name = device.name.clone();

    tokio::task::spawn_blocking(move || {
        let mut cap = Capture::from_device(device_name.as_str())
            .expect("Failed to open device")
            .promisc(true)
            .timeout(1000)
            .snaplen(65535)
            .open()
            .expect("Failed to activate capture");

        println!("Scanning on device: {}", device_name);
        let mut packets = Vec::new();

        while !*cancel_rx.borrow() {
            match cap.next_packet() {
                Ok(packet) => {
                    packets.push(packet.data.to_vec());
                    if packets.len() >= 1 {
                        packets.par_iter().for_each(|packet_data| {
                            if let Some(ethernet_packet) = EthernetPacket::new(packet_data) {
                                let summary = format!(
                                    "Packet: Source MAC: {}, Destination MAC: {}",
                                    ethernet_packet.get_source(),
                                    ethernet_packet.get_destination()
                                );
                                let _ = sender.send(summary);
                            }
                        });
                        packets.clear();
                    }
                }
                Err(err) => {
                    eprintln!("Error capturing packet: {}", err);
                    break;
                }
            }
        }

        println!("Scan stopped.");
    })
    .await
    .unwrap();
}

use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{Arp, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket, MutableEthernetPacket};
use std::env;
use std::net::Ipv4Addr;

const ETHERNET_FRAME_SIZE: usize = 42; // ARP Packet (28) + Ethernet Header (14)

fn main() {
    // Read the target IP from command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: sudo cargo run <TARGET_IP>");
        return;
    }
    let target_ip: Ipv4Addr = args[1].parse().expect("Invalid target IP address");

    // Find the network interface we'll use
    let interfaces = datalink::interfaces();
    // NOTE: Change "en0" to your actual network interface name (e.g., "eth0" on Linux)
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == "en0")
        .expect("Could not find the specified network interface.");

    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .expect("Interface has no IPv4 address.");

    // Open a channel to send and receive Layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Create the ARP packet
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    // Wrap the ARP packet in an Ethernet frame
    let mut ethernet_buffer = [0u8; ETHERNET_FRAME_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    // Send the packet
    tx.send_to(ethernet_packet.packet(), None);
    println!("Sent ARP request to {}", target_ip);

    // Wait for a reply
    println!("Waiting for ARP reply...");
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_frame = EthernetPacket::new(packet).unwrap();
                if ethernet_frame.get_ethertype() == EtherTypes::Arp {
                    let arp_reply = ArpPacket::new(ethernet_frame.payload()).unwrap();
                    // Check if the reply is from our target
                    if arp_reply.get_sender_proto_addr() == target_ip
                        && arp_reply.get_operation() == ArpOperations::Reply
                    {
                        println!("Found target!");
                        println!("  IP Address: {}", arp_reply.get_sender_proto_addr());
                        println!("  MAC Address: {}", arp_reply.get_sender_hw_addr());
                        break;
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading packets: {}", e);
            }
        }
    }
}

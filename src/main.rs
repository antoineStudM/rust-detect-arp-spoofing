use pnet::datalink;
use pnet::packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::{
    io::{self, Write},
    process::exit,
};

fn main() {
    let mut total_interface = 0;
    for interf in datalink::interfaces().iter() {
        println!("{}", interf);
        total_interface += 1;
    }

    print!("Choose your interface : ");
    let _ = io::stdout().flush(); // to write in the same line of the print!()
    let mut interface = String::new();
    io::stdin().read_line(&mut interface).unwrap();
    let interface_choice: usize = interface.trim().parse().unwrap_or_else(|_| {
        println!("[-] Bad interface choice... Exiting !");
        exit(1);
    });

    if interface_choice == 0 || interface_choice > total_interface {
        println!("[-] Bad interface choice... Exiting !");
        exit(1);
    }

    let interface = datalink::interfaces()[interface_choice - 1].clone();
    println!("\n[*] Interface selected : {}", interface);

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let mut ip_to_mac: HashMap<String, String> = HashMap::new();

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = packet::ethernet::EthernetPacket::new(packet).unwrap();
                if packet.get_ethertype() == packet::ethernet::EtherTypes::Arp {
                    let arp_packet = packet::arp::ArpPacket::new(packet.payload()).unwrap();

                    //if arp_packet.get_operation() == packet::arp::ArpOperation::new(2) {
                    detect_arp_spoofing(&arp_packet, &mut ip_to_mac);
                    //} else {
                    //   detect_arp_spoofing(&arp_packet, &mut ip_to_mac);
                    //}
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn detect_arp_spoofing(arp_packet: &ArpPacket, ip_to_mac: &mut HashMap<String, String>) {
    let sender_ip = arp_packet.get_sender_proto_addr().to_string();
    let sender_hw = arp_packet.get_sender_hw_addr().to_string();

    if let Some(existing_hw) = ip_to_mac.get(&sender_ip) {
        if existing_hw != &sender_hw {
            println!("[*] HACKING DETECTED !");
            println!(
                "{} : CHANGE MAC FROM {} TO {}",
                sender_ip, existing_hw, sender_hw
            );

            for (ip, mac) in ip_to_mac.iter() {
                if *mac == sender_hw {
                    println!("THE IP OF THE ATTACKER IS PROBABLY : {}",ip)
                }
            }
        }
    } else {
        ip_to_mac.insert(sender_ip, sender_hw);
    }
}

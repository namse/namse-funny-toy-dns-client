use dns_packet::*;
use std::net::{SocketAddr, UdpSocket};

mod dns_packet;

fn main() {
    /*
        - 1.1.1.1 혹은 8.8.8.8, 혹은 여러분의 ISP의 DNS로
            naver.com과 google.com에
            A, MX record 타입에 대한 query를 전송하고
            오는 응답을 전부 이쁘게 잘 꾸며서 출력할 것.
        - 응답에 여러 record가 오면 그것을 전부 다 출력할 것.
        - compression pointer도 처리할 것

        우리가 RFC를 읽고 난 후 알게 된 것
        1. Req, Res Packet 모양은 아주 똑같다.
        2. Text 처리를 어떻게 하는지 대강 안다! (5naver3com)
    */

    // DNS 서버를 고르고
    // --> DNS 서버 리스트를 받아서, 전부 처리해보지 뭐! 어떻게 다른지도 보고!

    let dns_server_addr_list = [
        SocketAddr::from(([1, 1, 1, 1], 53)),
        SocketAddr::from(([8, 8, 8, 8], 53)),
        SocketAddr::from(([219, 250, 36, 130], 53)),
        SocketAddr::from(([210, 220, 163, 82], 53)),
        SocketAddr::from(([168, 126, 63, 1], 53)),
        SocketAddr::from(([168, 126, 63, 2], 53)),
        SocketAddr::from(([164, 124, 101, 2], 53)),
        SocketAddr::from(([203, 248, 252, 2], 53)),
    ];

    // 쿼리 대상 도메인을 고르고
    let domain_name = ["naver.com", "google.com"];

    // A, MX 레코드에 대해서
    let record_types = [RecordType::A, RecordType::MX];

    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let mut packet_id = 0;

    // 쿼리를 만들어서 전송하고
    for dns_server_addr in dns_server_addr_list {
        for domain_name in domain_name {
            for record_type in record_types {
                packet_id += 1;
                let query_packet = DnsPacket::new_query(packet_id, domain_name, record_type);
                send_request(&udp_socket, &dns_server_addr, query_packet);
                let response_packet = receive_response(&udp_socket, &dns_server_addr, packet_id);
                print_result(&dns_server_addr, domain_name, record_type, response_packet);
            }
        }
    }
}

fn print_result(
    dns_server_addr: &SocketAddr,
    domain_name: &str,
    record_type: RecordType,
    response_packet: DnsPacket,
) {
    println!("{dns_server_addr} --> {domain_name} / {record_type:?}");
    println!("Response Packet: {:#?}", response_packet);
    println!();
}

fn receive_response(
    udp_socket: &UdpSocket,
    dns_server_addr: &SocketAddr,
    packet_id: u16,
) -> DnsPacket {
    let mut buf = [0; 512];
    loop {
        let (len, src_addr) = udp_socket.recv_from(&mut buf).unwrap();

        if &src_addr == dns_server_addr {
            let packet_buffer = &buf[..len];
            let response_packet = DnsPacket::from_buffer(packet_buffer);

            if response_packet.id == packet_id {
                return response_packet;
            }
        }
    }
}

fn send_request(udp_socket: &UdpSocket, dns_server_addr: &SocketAddr, packet: DnsPacket) {
    udp_socket
        .send_to(&packet.to_buffer(), dns_server_addr)
        .unwrap();
}

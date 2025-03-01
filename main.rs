use tokio::net::UdpSocket;
use trust_dns_proto::{
    op::{Message, MessageType, Query},
    rr::{DNSClass, Name, RData, Record, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use trust_dns_proto::rr::rdata::{MX, NULL};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let addr = "0.0.0.0:53".parse::<SocketAddr>().unwrap();
    let socket = UdpSocket::bind(addr).await.unwrap();
    println!("Listening on {}", addr);

    loop {
        let mut buf = [0u8; 512];
        let (len, src) = socket.recv_from(&mut buf).await.unwrap();

        match handle_query(&buf[..len]) {
            Ok(response) => {
                let _ = socket.send_to(&response, src).await;
            }
            Err(e) => eprintln!("Failed to handle query: {:?}", e),
        }
    }
}

fn handle_query(query_buf: &[u8]) -> Result<Vec<u8>, &'static str> {
    let query = Message::from_vec(query_buf).map_err(|_| "Failed to parse query")?;
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);

    if let Some(question) = query.queries().first() {
        response.add_query(question.clone());
        let answer = build_response(question);
        response.add_answer(answer);
    }

    let mut response_buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut response_buf);
        response.emit(&mut encoder).map_err(|_| "Failed to encode response")?;
    }
    
    Ok(response_buf)
}

fn build_response(query: &Query) -> Record {
    let name = query.name().clone();
    let record_type = query.query_type();
    let record_class = query.query_class();

    match (record_type, record_class) {
        (RecordType::A, DNSClass::IN) => {
            Record::from_rdata(name, 3600, RData::A([127, 0, 0, 1].into()))
        }
        (RecordType::AAAA, DNSClass::IN) => {
            Record::from_rdata(name, 3600, RData::AAAA("::1".parse().unwrap()))
        }
        (RecordType::CNAME, DNSClass::IN) => {
            Record::from_rdata(name, 3600, RData::CNAME(Name::from_ascii("example.com.").unwrap()))
        }
        (RecordType::MX, DNSClass::IN) => {
            let mx_record = MX::new(10, Name::from_ascii("mail.example.com.").unwrap());
            Record::from_rdata(name, 3600, RData::MX(mx_record))
        }
        (RecordType::NS, DNSClass::IN) => {
            Record::from_rdata(name, 3600, RData::NS(Name::from_ascii("ns.example.com.").unwrap()))
        }
        _ => {
            Record::from_rdata(name, 3600, RData::NULL(NULL::new()))
        }
    }
}

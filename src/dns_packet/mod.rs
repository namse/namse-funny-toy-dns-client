mod parse_name;
mod question;
mod record;

use parse_name::parse_name;
use question::*;
use record::*;

#[derive(Debug)]
pub struct DnsPacket {
    pub id: u16,
    query_or_response: QueryOrResponse,
    opcode: Opcode,
    authoritative_answer: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: ResponseCode,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    // name_servers: Vec<NameServer>,
    // additional_records: Vec<AdditionalRecord>,
}

impl DnsPacket {
    pub(crate) fn new_query(packet_id: u16, domain_name: &str, record_type: RecordType) -> Self {
        Self {
            id: packet_id,
            query_or_response: QueryOrResponse::Query,
            opcode: Opcode::StandardQuery,
            authoritative_answer: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            response_code: ResponseCode::NoError,
            questions: vec![Question::new(domain_name, record_type)],
            answers: vec![],
        }
    }

    pub(crate) fn to_buffer(&self) -> Vec<u8> {
        let mut buffer = vec![];

        // Header
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.push(
            (self.query_or_response as u8) << 7
                | (self.opcode as u8) << 3
                | (self.authoritative_answer as u8) << 2
                | (self.truncated as u8) << 1
                | (self.recursion_desired as u8),
        );
        buffer.push((self.recursion_available as u8) << 7 | (self.response_code as u8));
        buffer.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&0_u16.to_be_bytes());
        buffer.extend_from_slice(&0_u16.to_be_bytes());

        // Questions
        for question in &self.questions {
            question.extend_to_buffer(&mut buffer);
        }

        // NOTE: Below code is only needed for server
        // // Answers
        // for answer in &self.answers {
        //     answer.extend_to_buffer(&mut buffer);
        // }

        buffer
    }

    pub(crate) fn from_buffer(packet_buffer: &[u8]) -> DnsPacket {
        let id = u16::from_be_bytes([packet_buffer[0], packet_buffer[1]]);
        let query_or_response = match packet_buffer[2] >> 7 {
            0 => QueryOrResponse::Query,
            1 => QueryOrResponse::Response,
            _ => panic!("Invalid QueryOrResponse: {}", packet_buffer[2] >> 7),
        };
        let opcode = match (packet_buffer[2] >> 3) & 0b1111 {
            0 => Opcode::StandardQuery,
            1 => Opcode::InverseQuery,
            2 => Opcode::ServerStatusRequest,
            _ => panic!("Invalid Opcode: {}", (packet_buffer[2] >> 3) & 0b1111),
        };
        let authoritative_answer = (packet_buffer[2] >> 2) & 0b1 == 1;
        let truncated = (packet_buffer[2] >> 1) & 0b1 == 1;
        let recursion_desired = packet_buffer[2] & 0b1 == 1;
        let recursion_available = (packet_buffer[3] >> 7) & 0b1 == 1;
        let response_code = match packet_buffer[3] & 0b1111 {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => panic!("Invalid ResponseCode"),
        };
        let question_count = u16::from_be_bytes([packet_buffer[4], packet_buffer[5]]);
        let answer_count = u16::from_be_bytes([packet_buffer[6], packet_buffer[7]]);
        // let name_server_count = u16::from_be_bytes([packet_buffer[8], packet_buffer[9]]);
        // let additional_record_count = u16::from_be_bytes([packet_buffer[10], packet_buffer[11]]);

        let mut offset = 12;

        let questions = {
            let mut questions = vec![];
            for _ in 0..question_count {
                let question = Question::from_buffer(packet_buffer, &mut offset);
                questions.push(question);
            }
            questions
        };
        let answers = {
            let mut answers = vec![];
            for _ in 0..answer_count {
                let answer = ResourceRecord::from_buffer(packet_buffer, &mut offset);
                answers.push(answer);
            }
            answers
        };

        DnsPacket {
            id,
            query_or_response,
            opcode,
            authoritative_answer,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            questions,
            answers,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum QueryOrResponse {
    Query,
    Response,
}

#[derive(Clone, Copy, Debug)]
enum Opcode {
    StandardQuery,
    InverseQuery,
    ServerStatusRequest,
}

#[derive(Clone, Copy, Debug)]
enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RecordType {
    A,
    MX,
}

#[derive(Debug)]
enum QueryType {
    A, // 1 a host address
    // NS,    // 2 an authoritative name server
    // MD,    // 3 a mail destination (Obsolete - use MX)
    // MF,    // 4 a mail forwarder (Obsolete - use MX)
    // CNAME, // 5 the canonical name for an alias
    // SOA,   // 6 marks the start of a zone of authority
    // MB,    // 7 a mailbox domain name (EXPERIMENTAL)
    // MG,    // 8 a mail group member (EXPERIMENTAL)
    // MR,    // 9 a mail rename domain name (EXPERIMENTAL)
    // NULL,  // 10 a null RR (EXPERIMENTAL)
    // WKS,   // 11 a well known service description
    // PTR,   // 12 a domain name pointer
    // HINFO, // 13 host information
    // MINFO, // 14 mailbox or mail list information
    MX, // 15 mail exchange
        // TXT,   // 16 text strings
}

impl QueryType {
    fn to_u16(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::MX => 15,
        }
    }

    fn from_u16(value: u16) -> QueryType {
        match value {
            1 => QueryType::A,
            15 => QueryType::MX,
            _ => panic!("Invalid QueryType: {}", value),
        }
    }
}
#[derive(Debug)]
enum QueryClass {
    IN, // 1 the Internet
        // CS, // 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        // CH, // 3 the CHAOS class
        // HS, // 4 Hesiod [Dyer 87]
}

impl QueryClass {
    fn to_u16(&self) -> u16 {
        match self {
            QueryClass::IN => 1,
        }
    }

    fn from_u16(value: u16) -> QueryClass {
        match value {
            1 => QueryClass::IN,
            _ => panic!("Invalid QueryClass: {}", value),
        }
    }
}

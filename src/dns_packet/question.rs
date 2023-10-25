use super::*;

#[derive(Debug)]
pub(crate) struct Question {
    name: String,
    query_type: QueryType,
    query_class: QueryClass,
}
impl Question {
    pub(crate) fn new(domain_name: &str, record_type: RecordType) -> Question {
        Question {
            name: domain_name.to_string(),
            query_type: match record_type {
                RecordType::A => QueryType::A,
                RecordType::MX => QueryType::MX,
            },
            query_class: QueryClass::IN,
        }
    }

    pub(crate) fn extend_to_buffer(&self, buffer: &mut Vec<u8>) {
        for label in self.name.split('.') {
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0);

        buffer.extend_from_slice(&self.query_type.to_u16().to_be_bytes());
        buffer.extend_from_slice(&self.query_class.to_u16().to_be_bytes());
    }

    pub(crate) fn from_buffer(packet_buffer: &[u8], offset: &mut usize) -> Self {
        let name = parse_name(packet_buffer, offset);

        let query_type = QueryType::from_u16(u16::from_be_bytes([
            packet_buffer[*offset],
            packet_buffer[*offset + 1],
        ]));
        *offset += 2;

        let query_class = QueryClass::from_u16(u16::from_be_bytes([
            packet_buffer[*offset],
            packet_buffer[*offset + 1],
        ]));
        *offset += 2;

        Question {
            name,
            query_type,
            query_class,
        }
    }
}

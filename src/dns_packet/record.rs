use super::*;

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ResourceRecord {
    name: String,
    query_type: QueryType,
    query_class: QueryClass,
    ttl: u32,
    record_data: RecordData,
}
impl ResourceRecord {
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

        let ttl = u32::from_be_bytes([
            packet_buffer[*offset],
            packet_buffer[*offset + 1],
            packet_buffer[*offset + 2],
            packet_buffer[*offset + 3],
        ]);
        *offset += 4;

        let data_length = u16::from_be_bytes([packet_buffer[*offset], packet_buffer[*offset + 1]]);
        *offset += 2;

        let record_data = match query_type {
            QueryType::A => {
                assert_eq!(data_length, 4);

                let ip_address = u32::from_be_bytes([
                    packet_buffer[*offset],
                    packet_buffer[*offset + 1],
                    packet_buffer[*offset + 2],
                    packet_buffer[*offset + 3],
                ]);
                *offset += 4;

                RecordData::A(ip_address)
            }
            QueryType::MX => {
                let offset_before_parse = *offset;

                let preference =
                    u16::from_be_bytes([packet_buffer[*offset], packet_buffer[*offset + 1]]);
                *offset += 2;

                let exchange_name = parse_name(packet_buffer, offset);

                let parsed_data_length = *offset - offset_before_parse;
                assert_eq!(parsed_data_length, data_length as usize);

                RecordData::MX {
                    preference,
                    exchange_name,
                }
            }
        };

        ResourceRecord {
            name,
            query_type,
            query_class,
            ttl,
            record_data,
        }
    }
}

enum RecordData {
    A(u32),
    MX {
        preference: u16,
        exchange_name: String,
    },
}

impl std::fmt::Debug for RecordData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(arg0) => {
                let ip = std::net::Ipv4Addr::from(*arg0);
                f.debug_tuple("A").field(&ip).finish()
            }
            Self::MX {
                preference,
                exchange_name,
            } => f
                .debug_struct("MX")
                .field("preference", preference)
                .field("exchange_name", exchange_name)
                .finish(),
        }
    }
}

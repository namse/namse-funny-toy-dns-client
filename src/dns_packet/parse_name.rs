pub(crate) fn parse_name(packet_buffer: &[u8], offset: &mut usize) -> String {
    let mut name = String::new();

    loop {
        let label_header: u8 = packet_buffer[*offset];
        *offset += 1;

        let is_compression = label_header & 0xC0 == 0xC0;
        if is_compression {
            let mut pointer_offset =
                u16::from_be_bytes([label_header & 0x3F, packet_buffer[*offset]]) as usize;
            *offset += 1;

            let pointer_name = parse_name(packet_buffer, &mut pointer_offset);
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&pointer_name);
            return name;
        }

        assert_eq!((label_header & 0xC0), 0);

        let label_length = label_header;

        if label_length == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        let label =
            std::str::from_utf8(&packet_buffer[*offset..*offset + label_length as usize]).unwrap();
        name.push_str(label);
        *offset += label_length as usize;
    }

    name
}

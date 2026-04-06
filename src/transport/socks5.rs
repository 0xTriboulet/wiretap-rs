use std::io::{Read, Write};
use std::net::TcpStream;

pub(crate) fn parse_connect_port(stream: &mut TcpStream) -> Option<u16> {
    let ver = read_u8(stream)?;
    if ver != 0x05 {
        return None;
    }
    let nmethods = read_u8(stream)?;
    let methods = read_exact(stream, nmethods as usize)?;
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[0x05, 0xFF]);
        return None;
    }
    if stream.write_all(&[0x05, 0x00]).is_err() {
        return None;
    }

    let ver = read_u8(stream)?;
    if ver != 0x05 {
        return None;
    }
    let cmd = read_u8(stream)?;
    let _rsv = read_u8(stream)?;
    let atyp = read_u8(stream)?;
    if cmd != 0x01 {
        let _ = send_reply(stream, 0x07);
        return None;
    }
    if !discard_addr(stream, atyp) {
        let _ = send_reply(stream, 0x08);
        return None;
    }
    read_u16(stream)
}

pub(crate) fn send_reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    let reply = [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply)
}

fn discard_addr(stream: &mut TcpStream, atyp: u8) -> bool {
    match atyp {
        0x01 => read_exact(stream, 4).is_some(),
        0x03 => match read_u8(stream) {
            Some(len) => read_exact(stream, len as usize).is_some(),
            None => false,
        },
        0x04 => read_exact(stream, 16).is_some(),
        _ => false,
    }
}

fn read_u8(stream: &mut TcpStream) -> Option<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).ok()?;
    Some(buf[0])
}

fn read_u16(stream: &mut TcpStream) -> Option<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).ok()?;
    Some(u16::from_be_bytes(buf))
}

fn read_exact(stream: &mut TcpStream, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    Some(buf)
}

extern crate pnet;
extern crate byteorder;
extern crate failure;

use std::vec::Vec;
// use std::iter::Map;
use std::net::Ipv4Addr;
use pnet::util::MacAddr;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

const MAJIC_COOKIE_OFFSET: usize = 236;
const MAJIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const HTYPE_ETHER: u8 = 1;

#[derive(Debug)]
pub struct DHCPPacket {
    pub op: DHCPOperationCode,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: BFlag,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub options: Vec<Options>
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum DHCPOperationCode {
    Request = 1,
    Reply = 2
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum BFlag {
    Unicast = 0,
    Broadcast = 1
}

#[derive(PartialEq, Clone, Debug)]
pub struct DHCPOption {
    pub code: u8,
    pub data: Vec<u8>,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Options {
    SubnetMask(Ipv4Addr),
    RouterOption(Vec<Ipv4Addr>),
    DNSOption(Vec<Ipv4Addr>),
    IPTol(u8),
    RequestedIPAddress(Ipv4Addr),
    LeaseTime(u32),
    DHCPMessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    Message(String),
}

#[derive(PartialEq, Clone, Debug)]
pub enum MessageType {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEAS = 7
}

#[derive(Debug)]
pub enum OptionParseError {
    // #[fail(display = "decode failed")]
    ParseError,
    // #[fail(display = "unsupported option")]
    UnsupportError
}



impl DHCPPacket {
    pub fn new(buf: &[u8]) -> Result<DHCPPacket, failure::Error> {
        let op: DHCPOperationCode = match buf[0] {
            1 => DHCPOperationCode::Request,
            2 => DHCPOperationCode::Reply,
            _ => {
                return Err(failure::format_err!("invalid operation code"));
            }
        };
        let flag: BFlag = match buf[10] {
            0 => BFlag::Unicast,
            _ => BFlag::Broadcast
        };
        let packet = DHCPPacket {
            op: op,
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: Cursor::new(buf[4..8].to_vec()).read_u32::<BigEndian>().unwrap(),
            secs: Cursor::new(buf[8..10].to_vec()).read_u16::<BigEndian>().unwrap(),
            flags: flag,
            ciaddr: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            yiaddr: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            siaddr: Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]),
            giaddr: Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]),
            chaddr: MacAddr::new(buf[28], buf[29], buf[30], buf[31], buf[32], buf[33]),
            options: match decode_options(&buf[(MAJIC_COOKIE_OFFSET + 4)..]) {
                Ok(options) => options,
                Err(e) => return Err(failure::format_err!("failed to decode options: {:?}", e)),
            },
        };
        // should compare majic cookie.
        Ok(packet)
    }

    pub fn decode(&self) -> Option<Vec<u8>> {
        let mut data = vec![0u8; self.len()];
        debug!("length of buffer: {}", self.len());
        data[0] = match self.op {
            DHCPOperationCode::Request => 1,
            DHCPOperationCode::Reply => 2
        };
        data[1] = self.htype;
        data[2] = self.hlen;
        data[3] = self.hops;
        data[4..8].clone_from_slice(&[((self.xid >> 24) & 0xff) as u8, 
                                        ((self.xid >> 16) & 0xff) as u8,
                                        ((self.xid >> 8) & 0xff) as u8,
                                        (self.xid & 0xff) as u8]);
        data[8..10].clone_from_slice(&[((self.secs >> 8) & 0xff) as u8, (self.secs & 0xff) as u8]);
        let flag: &[u8] = match self.flags {
            BFlag::Unicast => &[0, 0],
            BFlag::Broadcast => &[128 ,0]
        };
        data[10..12].clone_from_slice(flag);
        data[12..16].clone_from_slice(&self.ciaddr.octets());
        data[16..20].clone_from_slice(&self.yiaddr.octets());
        data[20..24].clone_from_slice(&self.siaddr.octets());
        data[24..28].clone_from_slice(&self.giaddr.octets());
        data[28..34].clone_from_slice(&macaddr_to_slice(self.chaddr));
        data[34..MAJIC_COOKIE_OFFSET].clone_from_slice(&[0u8; 202]);
        data[MAJIC_COOKIE_OFFSET..(MAJIC_COOKIE_OFFSET + 4)].clone_from_slice(&MAJIC_COOKIE);
        // serialize options
        let mut offset = MAJIC_COOKIE_OFFSET + 4;
        let optoins_len = self.options.iter().map(|op| op.len() + 2);
        for (l, op) in optoins_len.zip(self.options.iter()) {
            let o = match op.decode() {
                Some(o) => o,
                None => return None
            };
            data[offset..(offset + l)].clone_from_slice(&o);
            offset += l;
        }
        // add end byte
        data[offset] = 0xff;
        Some(data)
    }

    fn len(&self) -> usize {
        34 + 202 + 4 + 1 + self.options.iter().fold(0, |sum, op| sum + 2 + op.len())
    }

    pub fn operation(&self) -> DHCPOperationCode {
        self.op
    }

    pub fn get_options(&self) -> &[Options] {
        &self.options
    }

    pub fn create_reply_packet(xid: u32, 
        yiaddr: Ipv4Addr,
        giaddr: Ipv4Addr,
        ciaddr: Option<Ipv4Addr>,
        flag: BFlag,
        chaddr: MacAddr,
        options: Vec<Options>
    ) -> Result<DHCPPacket, failure::Error> {

        let reply = DHCPPacket {
            op: DHCPOperationCode::Reply,
            htype: HTYPE_ETHER,
            hlen: 6 as u8,
            hops: 0 as u8,
            xid: xid,
            secs: 0 as u16,
            flags: flag,
            ciaddr: if let Some(ciaddr) = ciaddr {
                ciaddr
            } else {
                Ipv4Addr::new(0, 0, 0, 0)
            },
            yiaddr: yiaddr,
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            giaddr: giaddr,
            chaddr: chaddr,
            options: options,
        };
        Ok(reply)
    }    
}

impl Options {
    pub fn new(code: u8, len: u8, data: &[u8]) -> Result<Options, OptionParseError> {
        match code {
            SUBNET_MASK => Ok(Options::SubnetMask(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            ROUTER_OPTION => {
                let mut addresses: Vec<Ipv4Addr> = Vec::new();
                for i in 0..(len / 4) {
                    let b = &data[(i as usize)..((i as usize) + 4)];
                    addresses.push(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                }
                Ok(Options::RouterOption(addresses))
            },
            DOMAIN_NAME_SERVER_OPTION => {
                let mut addresses: Vec<Ipv4Addr> = Vec::new();
                for i in 0..(len / 4) {
                    let b = &data[(i as usize)..((i as usize) + 4)];
                    addresses.push(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                }
                Ok(Options::DNSOption(addresses))
            },
            DEFAULT_IP_TOL => Ok(Options::IPTol(data[0])),
            REQUESTED_IPADDRESS => Ok(Options::RequestedIPAddress(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            IP_ADDRESS_LEASE_TIME => Ok(Options::LeaseTime(Cursor::new(data.to_vec()).read_u32::<BigEndian>().unwrap())),
            DHCP_MESSAGE_TYPE => {
                match data[0] {
                    1 => Ok(Options::DHCPMessageType(MessageType::DHCPDISCOVER)),
                    2 => Ok(Options::DHCPMessageType(MessageType::DHCPOFFER)),
                    3 => Ok(Options::DHCPMessageType(MessageType::DHCPREQUEST)),
                    4 => Ok(Options::DHCPMessageType(MessageType::DHCPDECLINE)),
                    5 => Ok(Options::DHCPMessageType(MessageType::DHCPACK)),
                    6 => Ok(Options::DHCPMessageType(MessageType::DHCPNAK)),
                    7 => Ok(Options::DHCPMessageType(MessageType::DHCPRELEAS)),
                    _ => Err(OptionParseError::UnsupportError),
                }
            },
            SERVER_IDENTIFIER => Ok(Options::ServerIdentifier(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            MESSAGE => {
                match String::from_utf8(data.to_vec()) {
                    Ok(message) => Ok(Options::Message(message)),
                    Err(_) => Err(OptionParseError::ParseError),
                }                
            },
            _ => {
                // debug!("unhandled dhcp options");
                // println!("code:{}, data:{:?}", code, data);
                Err(OptionParseError::UnsupportError)
            }
        }
    }

    pub fn decode(&self) -> Option<Vec<u8>> {
        match self {
            Options::DHCPMessageType(typ) => Some(vec![DHCP_MESSAGE_TYPE, 1, match typ {
                MessageType::DHCPDISCOVER => 1,
                MessageType::DHCPOFFER => 2,
                MessageType::DHCPREQUEST => 3,
                MessageType::DHCPDECLINE => 4,
                MessageType::DHCPACK => 5,
                MessageType::DHCPNAK => 6,
                MessageType::DHCPRELEAS => 7,
            }]),
            Options::SubnetMask(addr) => {
                let addr = addr.octets();
                Some(vec![SUBNET_MASK, 4, addr[0], addr[1], addr[2], addr[3]])
            },
            Options::RouterOption(addresses) => {
                let mut buf: Vec<u8> = vec![ROUTER_OPTION, (addresses.len() * 4) as u8];
                // addresses.iter().map(|addr| {
                //     buf.append(&mut addr.octets().to_vec());
                // });
                for addr in addresses.iter() {
                    buf.append(&mut addr.octets().to_vec());
                }
                Some(buf)
            },
            Options::DNSOption(addresses) => {
                let mut buf: Vec<u8> = vec![DOMAIN_NAME_SERVER_OPTION, (addresses.len() * 4) as u8];
                for addr in addresses.iter() {
                    buf.append(&mut addr.octets().to_vec());
                }
                Some(buf)
            },
            Options::IPTol(tol) => Some(vec![DEFAULT_IP_TOL, 1, *tol]),
            Options::RequestedIPAddress(addr) => {
                let addr = addr.octets();
                Some(vec![REQUESTED_IPADDRESS, 4, addr[0], addr[1], addr[2], addr[3]])
            },
            Options::LeaseTime(time) => {
                Some(vec![IP_ADDRESS_LEASE_TIME, 4, ((time >> 24) as u16 & 0xff) as u8,
                                                    ((time >> 16) as u16 & 0xff) as u8,
                                                    ((time >> 8) as u16 & 0xff) as u8,
                                                    (time & 0xff) as u8])
            },
            Options::ServerIdentifier(addr) => {
                let addr = addr.octets();
                Some(vec![SERVER_IDENTIFIER, 4, addr[0], addr[1], addr[2], addr[3]])
            },
            Options::Message(msg) => {
                let mut buf: Vec<u8> = vec![MESSAGE, msg.len() as u8];
                buf.append(&mut msg.as_bytes().to_vec());
                Some(buf)
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Options::DHCPMessageType(_) => 1,
            Options::SubnetMask(_) => 4,
            Options::RouterOption(r) => r.len() * 4,
            Options::DNSOption(d) => d.len() * 4,
            Options::IPTol(_) => 1,
            Options::RequestedIPAddress(_) => 4,
            Options::LeaseTime(_) => 4,
            Options::ServerIdentifier(_) => 4,
            Options::Message(msg) => msg.len()
        }
    }
}

pub fn is_requested_address<'a >(options: &'a Vec<Options>) -> Option<&'a Ipv4Addr> {
    if let Some(op) = options.iter().find(|op| match op {
        Options::RequestedIPAddress(_) => true,
        _ => false
    }) {
        match op {
            Options::RequestedIPAddress(addr) => Some(addr),
            _ => None
        }

    } else {
        None
    }
}

// fn encode_options(options: Vec<Options>) -> Option<&[u8]> {
//     let length = options.iter().fold(0, |l, op| l + op.len() + 2);
//     let options = options.iter().map(|option| option.decode().unwrap() );
//     options.fold()
// }

fn decode_options(data: &[u8]) -> Result<Vec<Options>, failure::Error> {
    let mut options: Vec<Options> = Vec::new();
    let mut code_offset = 0;
    let mut length_offset = 1;
    while data[code_offset] != END {
        let length = data[length_offset];
        match Options::new(data[code_offset], length, &data[(length_offset + 1)..(length_offset + 1 + (length as usize))]) {
            Ok(op) => {
                options.push(op);
                code_offset += (length + 2) as usize;
                length_offset += (length + 2) as usize;
            },
            Err(e) => match e {
                OptionParseError::ParseError => return Err(failure::format_err!("failed to parse option")),
                OptionParseError::UnsupportError => {
                    code_offset += (length + 2) as usize;
                    length_offset += (length + 2) as usize;
                } // println!("unsupported options found"),
            }
        }
    }
    Ok(options)
}

fn macaddr_to_slice(addr: MacAddr) -> [u8; 6] {
    [addr.0, addr.1, addr.2, addr.3, addr.4, addr.5]
}

const SUBNET_MASK: u8 = 1;
// const TIME_OFFSET: u8 = 2;
const ROUTER_OPTION: u8 = 3;
// const TIME_SERVER_OPTION: u8 = 4;
// const NAME_SERVER_OPTION: u8 = 5;
const DOMAIN_NAME_SERVER_OPTION: u8 = 6;
// const LOG_SERVER_OPTION: u8 = 7;
// const COOKIE_SERVER_OPTION: u8 = 8;
// const LPR_SERVER_OPTION: u8 = 9;
// const IMPRESS_SERVER_OPTION: u8 = 10;
const DEFAULT_IP_TOL: u8 = 23;

const REQUESTED_IPADDRESS: u8 = 50;
const IP_ADDRESS_LEASE_TIME: u8 = 51;
// const OPTION_OVERLOAD: u8 = 52;
const DHCP_MESSAGE_TYPE: u8 = 53;

const SERVER_IDENTIFIER: u8 = 54;

const MESSAGE: u8 = 56;

const END: u8 = 255;

#[cfg(test)]
mod tests {
    #[test]
    fn test_new_option_dhcp_message_type() {
        let code = 53;
        let len = 1;
        let data: &[u8] = &[1];
        assert_eq!(super::Options::DHCPMessageType(super::MessageType::DHCPDISCOVER), 
        super::Options::new(code, len, data).unwrap());
    }
    #[test]
    fn test_option_decode() {
        let option = super::Options::new(1, 4, &[127,0,0,1]).unwrap();
        assert_eq!(option.decode().unwrap(), vec![1, 4, 127, 0, 0, 1]);
    }

    #[test]
    fn test_decode_options() {
        let data = [
            0x35, 0x01, 0x01, // DHCP Option Type DHCPDISCOVER
            0x01, 0x04, 0xff, 0xff, 0xff, 0x00, // subnet mask 255.255.255.0
            0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, // router option 192.168.0.1
            0x06, 0x04, 0x08, 0x08, 0x08, 0x08, // dns option 8.8.8.8
            0x32, 0x04, 0xc0, 0xa8, 0x00, 0x05, // requested ip 192.168.0.5
            0xff, // end
        ];
        let options = super::decode_options(&data).unwrap();
        println!("{:?}", options);
        assert_eq!(options[0],
            super::Options::DHCPMessageType(super::MessageType::DHCPDISCOVER));
        assert_eq!(options[1],
            super::Options::SubnetMask(super::Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(options[2],
            super::Options::RouterOption(vec!(super::Ipv4Addr::new(192, 168, 0, 1))));
        assert_eq!(options[3],
            super::Options::DNSOption(vec!(super::Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(options[4],
            super::Options::RequestedIPAddress(super::Ipv4Addr::new(192, 168, 0, 5)));
    }
    #[test]
    fn test_new_packet() {
        let data = [
            // first fields (op, secs, flags, addrs...)
            0x01, 0x01, 0x06, 0x00, 0x6e, 0x86, 0x44, 0x4c,
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x52, 0x54, 0x01, 0x12,
            0x34, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // sname
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            // file
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            // majic cookie
            99, 130, 83, 99,

            // options
            0x35, 0x01, 0x01, // DHCP Option Type DHCPDISCOVER
            0x01, 0x04, 0xff, 0xff, 0xff, 0x00, // subnet mask 255.255.255.0
            0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, // router option 192.168.0.1
            0x06, 0x04, 0x08, 0x08, 0x08, 0x08, // dns option 8.8.8.8
            0x32, 0x04, 0xc0, 0xa8, 0x00, 0x05, // requested ip 192.168.0.5
            0x3d, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // client identifier
            0xff, // end
        ];
        let packet = super::DHCPPacket::new(&data).unwrap();

        assert_eq!(packet.op, super::DHCPOperationCode::Request);
    }

    #[test]
    fn test_decode() {
        let data = [
            // first fields (op, secs, flags, addrs...)
            0x01, 0x01, 0x06, 0x00, 0x6e, 0x86, 0x44, 0x4c,
            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x52, 0x54, 0x01, 0x12,
            0x34, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // sname
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            // file
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

            // majic cookie
            99, 130, 83, 99,

            // options
            0x35, 0x01, 0x01, // DHCP Option Type DHCPDISCOVER
            0x01, 0x04, 0xff, 0xff, 0xff, 0x00, // subnet mask 255.255.255.0
            0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, // router option 192.168.0.1
            0x06, 0x04, 0x08, 0x08, 0x08, 0x08, // dns option 8.8.8.8
            0x32, 0x04, 0xc0, 0xa8, 0x00, 0x05, // requested ip 192.168.0.5
            0xff, // end
        ];
        let packet = super::DHCPPacket::new(&data).unwrap();
        assert_eq!(packet.len(), data.len());
        println!("pass length test");
        assert_eq!(packet.decode().unwrap(), data.to_vec());
    }

    #[test]
    fn test_get_options() {
        let discover = super::Options::new(53, 1, &[1]).unwrap();
        let request = super::Options::new(50, 4, &[192,168,0,5]).unwrap();
        let options = vec![discover, request];
        assert_eq!(&super::Ipv4Addr::new(192,168, 0, 5), super::is_requested_address(&options).unwrap());
    }
}

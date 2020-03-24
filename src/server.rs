extern crate yaml_rust;

use std::net::{Ipv4Addr, UdpSocket, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use ipnetwork::Ipv4Network;
use yaml_rust::{Yaml, YamlLoader};
use std::fs;
use std::str::FromStr;
use pnet::util::MacAddr;
use super::storage::*;
use super::dhcp::*;

#[derive(Debug)]
pub struct DHCPServer {
    pub addr: Ipv4Addr,
    pub port: u32,
    pub pool: Ipv4Network,
    // pub pool: Mutex<Vec<Ipv4Addr>>,
    pub storage: Mutex<Storage>,
    pub router: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub lease_time: u32,
}

pub struct Config {
    pub addr: Ipv4Addr,
    pub port: u32,
    pub pool: Ipv4Network,
    pub router: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub lease_time: u32
}

impl DHCPServer {
    pub fn new(config: &Config) -> DHCPServer {
        DHCPServer {
            addr: config.addr,
            port: config.port,
            pool: config.pool,
            router: config.router,
            dns_server: config.dns,
            lease_time: config.lease_time,
            subnet_mask: config.pool.mask(),
            storage: Mutex::new(Storage::new()), // DHCPServer構造体の他のフィールドは書き換えられないが，Storageだけは書き換えられるので単体で持った方がいい？
        }
    }
}

impl DHCPServer {
    fn handle(&self, socket: &UdpSocket, packet: &DHCPPacket) -> Result<(), failure::Error> {
        let options = packet.get_options();
        // let message_type = &options[0];
        match &options[0] {
            Options::DHCPMessageType(typ) => {
                match typ {
                    MessageType::DHCPDISCOVER => self.dhcp_discover_handle(socket, packet)?,
                    // MessageType::DHCPOFFER => 
                    MessageType::DHCPREQUEST => self.dhcp_request_handle(socket, packet)?,
                    // MessageType::DHCPDECLINE =>
                    // MessageType::DHCPACK =>
                    // MessageType::DHCPNAK =>
                    MessageType::DHCPRELEAS => self.dhcp_request_handle_release(socket, packet)?,
                    _ => return Err(failure::format_err!("Unhandlable message type"))
                }
            },
            _ => return Err(failure::format_err!("dhcp option type is not found")),
        }
        Ok(())
    }

    fn dhcp_discover_handle(&self, socket: &UdpSocket, packet: &DHCPPacket) -> Result<(), failure::Error> {
        println!("DHCP DISCOVER");
        
        let requested_address = is_requested_address(&packet.options);
        let leased_addr = self.lease_address(packet.xid, packet.chaddr, requested_address)?;
        // ignore packet.giaddr because this server don't handle relay agent
        // create DHCPOFFER message
        let reply = DHCPPacket::create_reply_packet(
            packet.xid,
            leased_addr,
            packet.giaddr,
            None,
            packet.flags,
            packet.chaddr,
            self.create_options(2)
        )?;
        println!("-------- reply packet DHCPOFFER ----------");
        println!("{:?}", packet);
        let buf = reply.decode().expect("failed to decode reply packet");
        // broadcast
        broadcast(socket, &buf)?;
        Ok(())
    }

    fn dhcp_request_handle(&self, socket: &UdpSocket, packet: &DHCPPacket) -> Result<(), failure::Error> {
        println!("DHCP REQUEST");
        // is it set server identifier opton?
        if let Some(server_identifier) = packet.options
            .iter()
            .find(|op| match *op {
                Options::ServerIdentifier(_) => true,
                _ => false,
            }) {
                // reply of DHCPOFFER
                let server_ip = match server_identifier {
                    Options::ServerIdentifier(ip) => ip,
                    _ => return Err(failure::format_err!("server identifier is invalid")),
                };
            return self.dhcp_request_handle_selecting(*server_ip, socket, packet)
        } else {
            return self.dhcp_request_handle_re(socket, packet)
        }
    }

    fn dhcp_request_handle_selecting(&self, server_ip: Ipv4Addr, socket: &UdpSocket, packet: &DHCPPacket) -> Result<(), failure::Error> {
        if server_ip != self.addr {
            println!("client choose other dhcp server");
            return Ok(());
        }
        let requested_addr = is_requested_address(&packet.options).expect("requested ip address is not set");

        let mut s = self.storage.lock().expect("failed to lock storage"); // ここロックしていい？

        match s.search_from_mac(&packet.chaddr) {
            Ok(_) => {
                // update
                let entry = Entry::new(packet.xid, *requested_addr, packet.chaddr);
                s.update(&entry)?;
            },
            Err(_) => {
                // insert
                let entry = Entry::new(packet.xid, *requested_addr, packet.chaddr);
                s.add(&entry);
            }
        }
        // create DHCPACK packet
        let options = self.create_options(5);
        let reply = DHCPPacket::create_reply_packet(
            packet.xid,
            *requested_addr,
            packet.giaddr,
            None, // 埋めないといけないかも
            packet.flags,
            packet.chaddr,
            options
        )?;
        println!("-------- reply packet DHCPACK ----------");
        println!("{:?}", reply);
        let buf = reply.decode().expect("failed to decode reply packet");
        broadcast(socket, &buf)?;
        Ok(())
    }

    fn dhcp_request_handle_re(&self, socket: &UdpSocket, packet: &DHCPPacket) -> Result<(), failure::Error> {
        if let Some(addr) = is_requested_address(&packet.options) {
            // init-reboot
            println!("ININ-REBOOT");
            {
                let s = self.storage.lock().unwrap();
                match s.search_from_mac(&packet.chaddr) {
                    Ok(a) => {
                        if *addr == a {
                            let options = self.create_options(5);
                            let reply = DHCPPacket::create_reply_packet(
                                packet.xid,
                                *addr,
                                packet.giaddr,
                                None,
                                packet.flags,
                                packet.chaddr,
                                options
                            )?;
                            let buf = reply.decode().expect("failed to decode reply packet");
                            broadcast(socket, &buf)?;
                            return Ok(());
                        } else {
                            // reply DHCPACK
                            let options = self.create_options(6);
                            let reply = DHCPPacket::create_reply_packet(
                                packet.xid,
                                *addr,
                                packet.giaddr,
                                None,
                                packet.flags,
                                packet.chaddr,
                                options
                            )?;
                            let buf = reply.decode().expect("failed to decode reply packet");
                            broadcast(socket, &buf)?;
                            return Ok(());
                        }
                    },
                    Err(_) => {
                        return Ok(())
                    },
                }
            }
        } else {
            // requested address is invalid
            println!("RENEWING or REBINDING");
            let options = self.create_options(6);
            let reply = DHCPPacket::create_reply_packet(
                packet.xid,
                Ipv4Addr::new(0,0,0,0),
                packet.giaddr,
                None,
                packet.flags,
                packet.chaddr,
                options
            )?;
            let buf = reply.decode().expect("failed to decode reply packet");
            broadcast(socket, &buf)?;
            Ok(())
        }
    }

    fn dhcp_request_handle_release(&self, socket: &UdpSocket, packet: &DHCPPacket) -> Result<(), failure::Error> {
        println!("DHCP RELEASE");
        // release leased ip address
        let mut s = self.storage.lock().unwrap();
        s.delete_by_ip(&packet.ciaddr)?;
        println!("delete leased ip: {:?}", packet.ciaddr);
        Ok(())
    }

    fn lease_address(&self, xid: u32, chaddr: MacAddr, requested: Option<&Ipv4Addr>) -> Result<Ipv4Addr, failure::Error> {
        // lock
        let mut s = self.storage.lock().unwrap();
        let used_address = vec![self.router, self.dns_server, self.pool.network()];
        // search an entry from storage by mac address
        if let Ok(addr) = s.search_from_mac(&chaddr) {
            return Ok(addr);
        }
        // requested ip address
        if let Some(addr) = requested {
            if !self.is_available_address(*addr) {
                return Err(failure::format_err!("requested address is already used"))
            }
            match s.search_from_ip(&addr) {
                Ok(_) => {
                    println!("requested address is not available");
                    let addr = s.find_available_address(self.pool, used_address)
                                .expect("There is no available address");
                    // s.add(&Entry::new(xid, addr, chaddr));
                    return Ok(addr);
                },
                Err(_) => {
                    // requested address is available
                    // s.add(&Entry::new(xid, addr, chaddr));
                    return Ok(*addr);
                },
            }
        }
        // 
        let addr = s.find_available_address(self.pool, used_address).expect("there is no available address");
        s.add(&Entry::new(xid, addr, chaddr));
        Ok(addr)
    }

    fn create_options(&self, message_type_code: u8) -> Vec<Options> {
        let typ = Options::new(53, 1, &[message_type_code]).unwrap(); // DHCPOFFER
        let server_identifier = Options::new(54, 4, &self.addr.octets()).unwrap();
        let subnet_mask = Options::new(1, 4, &self.subnet_mask.octets()).unwrap();
        let router = Options::new(3, 4, &self.router.octets()).unwrap();
        let dns = Options::new(6, 4, &self.dns_server.octets()).unwrap();
        let time = self.lease_time;
        let lease_time = Options::new(51, 4, &[((time >> 24) as u16 & 0xff) as u8,
                                                ((time >> 16) as u16 & 0xff) as u8,
                                                ((time >> 8) as u16 & 0xff) as u8,
                                                (time & 0xff) as u8]).unwrap(); 
        vec![typ, server_identifier, subnet_mask, router, dns, lease_time]
    }

    fn is_available_address(&self, addr: Ipv4Addr) -> bool {
        if addr == self.addr || addr == self.router || addr == self.dns_server {
            false 
        } else {
            true
        }
    }
}

pub fn serve(path: &str) {
    let config = load_config(path);
    let socket = UdpSocket::bind(create_addr_string(&Ipv4Addr::new(0,0,0,0), config.port)).expect("Failed to bind socket");
    socket.set_broadcast(true).unwrap();

    let server = Arc::new(DHCPServer::new(&config));
    println!("---------- dhcp server start ----------");
    println!("{:?}", server);
    println!("---------------------------------------");
    loop {
        let mut buffer = [0u8; 2048];
        match socket.recv_from(&mut buffer) {
            Ok((len, addr)) => {
                println!("received {}bytes from {:?}", len, addr);
                // clone
                let server = server.clone();
                let socket = socket.try_clone().expect("failed to clone socket.");
                // create new thread
                thread::spawn(move || {
                    println!("create new thread.");
                    match DHCPPacket::new(&buffer) {
                        Ok(packet) => {
                            println!("{:?}", packet);
                            if packet.operation() == DHCPOperationCode::Reply {
                                return
                            }
                            match server.handle(&socket, &packet) {
                                Ok(_) => {},
                                Err(e) => println!("handling error: {:?}", e),
                            }
                        },
                        Err(e) => println!("failed to decode packet: {:?}", e),
                    }
                });
            },
            Err(e) => {
                error!("failed to receive data from socket: {:?}", e);
            }
        }
    }
}

fn broadcast(socket: &UdpSocket, buf: &[u8]) -> Result<(), failure::Error> {
    let destination: SocketAddr = "255.255.255.255:68".parse()?;
    socket.send_to(buf, destination)?;
    Ok(())
}

pub fn load_config(path: &str) -> Config {
    let config: String = fs::read_to_string(path).unwrap();
    let config = YamlLoader::load_from_str(&config).unwrap();
    let config = &config[0];
    let addr = match &config["address"] {
        Yaml::String(addr) => Ipv4Addr::from_str(&addr).unwrap(),
        _ => Ipv4Addr::new(127,0,0,1),
    };
    let port = match config["port"] {
        Yaml::Integer(i) => i as u32,
        _ => 67 // default port
    };
    let pool = match &config["pool"] {
        Yaml::String(addr) => Ipv4Network::from_cidr(&addr).unwrap(),
        _ => panic!("Invalid pool")
    };
    let router = match &config["router"] {
        Yaml::String(router) => Ipv4Addr::from_str(&router).unwrap(),
        _ => panic!("Invalid router address")
    };
    let dns = match &config["dns"] {
        Yaml::String(dns) => Ipv4Addr::from_str(&dns).unwrap(),
        _ => panic!("Invalid dns address")
    };
    let lease_time = match config["lease_time"] {
        Yaml::Integer(time) => time as u32,
        _ => panic!("Invalid lease time")
    };
    Config {
        addr: addr,
        port: port,
        pool: pool,
        router: router,
        dns: dns,
        lease_time: lease_time,
    }
}

fn create_addr_string(addr: &Ipv4Addr, port: u32) -> String {
    let addr = addr.octets();
    format!("{}.{}.{}.{}:{}", addr[0].to_string(), addr[1].to_string(), addr[2].to_string(), addr[3].to_string(), port.to_string())
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_load_config() {
        let path = "./config.yaml";
        let config = super::load_config(&path);
        let addr = super::Ipv4Addr::new(192, 168, 0, 1);
        assert_eq!(config.router, addr);
        assert_eq!(config.addr, super::Ipv4Addr::new(0,0,0,0));
        
    }

    #[test]
    fn test_create_addr_string() {
        let addr = super::Ipv4Addr::new(127,0,0,1);
        let port = 67;

        let addr_string = super::create_addr_string(&addr, port);
        assert_eq!(addr_string, "127.0.0.1:67");
    }

    #[test]
    fn test_ipv4_network() {
        let subnet = super::Ipv4Network::from_cidr("192.168.0.0/24").unwrap();
        let mut subnet_iterator: Vec<super::Ipv4Addr> = subnet.iter().filter(|addr| true ).collect();
        // println!("{:?}", subnet_iterator);
        // assert_eq!(subnet_iterator.next().unwrap(), super::Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn test_lease_address() {
        let config = super::load_config("./config.yaml");
        let server = super::DHCPServer::new(&config);
        let leased_addr = server.lease_address(1, 
            super::MacAddr::new(1,1,1,1,1,1),
            None);
        if let Ok(addr) = leased_addr {
            println!("{:?}", server.storage);
            assert_eq!(addr, super::Ipv4Addr::new(192, 168, 0, 2));
        } else {
            panic!("failed to test");
        }
    }

    #[test]
    fn test_lease_address_requested() {
        let config = super::load_config("./config.yaml");
        let server = super::DHCPServer::new(&config);
        let leased_addr = server.lease_address(1, 
            super::MacAddr::new(1,1,1,1,1,1),
            Some(&super::Ipv4Addr::new(192,168,0,5)));
        match leased_addr {
            Ok(addr) => {
                println!("{:?}", server.storage);
                assert_eq!(addr, super::Ipv4Addr::new(192, 168, 0, 5));
            },
            Err(e) => panic!("failed to test {}", e),
        }
    }

    #[test]
    fn test_handle() {

    }
}

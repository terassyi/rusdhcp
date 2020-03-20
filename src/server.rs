extern crate yaml_rust;

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use ipnetwork::Ipv4Network;
use yaml_rust::{Yaml, YamlLoader};
use std::fs;
use std::str::FromStr;
use super::storage::*;

pub struct DHCPServer {
    pub addr: Ipv4Addr,
    pub port: u32,
    pub pool: Ipv4Network,
    // pub storage: Storage,
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
            // storage: Storage::new(), // DHCPServer構造体の他のフィールドは書き換えられないが，Storageだけは書き換えられるので単体で持った方がいい？
        }
    }
}

pub fn serve(path: &str) {
    let config = load_config(path);
    let socket = UdpSocket::bind(create_addr_string(&config.addr, config.port)).expect("Failed to bind socket");
    socket.set_broadcast(true).unwrap();

    let server = Arc::new(DHCPServer::new(&config));
    let storage = Arc::new(Mutex::new(Storage::new()));
    
    loop {
        let mut buffer = [0u8; 2048];
        match socket.recv_from(&mut buffer) {
            Ok((len, addr)) => {
                debug!("received {}bytes from {:?}", len, addr);
            },
            Err(e) => {
                error!("failed to receive data from socket: {:?}", e);
            }
        }
    }
}


pub fn load_config(path: &str) -> Config {
    let config: String = fs::read_to_string(path).unwrap();
    let config = YamlLoader::load_from_str(&config).unwrap();
    let config = &config[0];
    println!("{:?}", config);
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
    println!("{:?}", router);
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
}

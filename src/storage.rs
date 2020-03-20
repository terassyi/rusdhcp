
use std::vec::Vec;
use failure;
use std::net::Ipv4Addr;
use pnet::util::MacAddr;

pub struct Storage {
    pub entries: Vec<Entry>
}

#[derive(PartialEq, Clone, Copy)]
pub struct Entry {
    pub id: u32,
    pub ip_addr: Ipv4Addr,
    pub mac_addr: MacAddr,
}

impl Storage {
    pub fn new() -> Storage {
        Storage {
            entries: Vec::new(),
        }
    }

    pub fn add(mut self, entry: &Entry) {
        self.entries.push(*entry);
    }

    pub fn search_from_ip(&self, addr: &Ipv4Addr) -> Option<Entry> {
        for e in self.entries.iter() {
            if e.ip_addr == *addr {
                return Some(*e)
            }
        }
        None
    }

    pub fn search_from_mac(&self, addr: &MacAddr) -> Option<Entry> {
        for e in self.entries.iter() {
            if e.mac_addr == *addr {
                return Some(*e)
            }
        }
        None
    }

    // pub fn delete(&mut self, ip_addr: Option<Ipv4Addr>, mac_addr: Option<MacAddr>) -> Result<Self, failure::Error> {
    //     match ip_addr {
    //         Some(addr) => {

    //         }
    //     }
    // }
}

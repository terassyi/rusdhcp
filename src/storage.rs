
use std::vec::Vec;
use failure;
use std::net::Ipv4Addr;
use pnet::util::MacAddr;
use ipnetwork::Ipv4Network;

#[derive(Debug, Clone)]
pub struct Storage {
    pub entries: Vec<Entry>
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct Entry {
    pub id: u32,
    pub ip_addr: Ipv4Addr,
    pub mac_addr: MacAddr,
}

impl Entry {
    pub fn new(id: u32, ip_addr: Ipv4Addr, mac_addr: MacAddr) -> Entry {
        Entry {
            id: id,
            ip_addr: ip_addr,
            mac_addr: mac_addr,
        }
    }
}

impl Storage {
    pub fn new() -> Storage {
        Storage {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: &Entry) {
        self.entries.push(*entry);
    }

    pub fn update(&mut self, entry: &Entry) -> Result<(), failure::Error> {
        let index = self.index(&entry.mac_addr)?;
        self.entries.remove(index);
        self.add(entry);
        Ok(())
    }

    pub fn index(&self, mac_addr: &MacAddr) -> Result<usize, failure::Error> {
        let mut count = 0;
        for e in self.entries.iter() {
            if e.mac_addr == *mac_addr {
                return Ok(count);
            }
            count += 1;
        }
        Err(failure::format_err!("not found"))
    }

    pub fn index_from_ip(&self, ip_addr: &Ipv4Addr) -> Result<usize, failure::Error> {
        let mut count = 0;
        for e in self.entries.iter() {
            if e.ip_addr == *ip_addr {
                return Ok(count);
            }
            count += 1;
        }
        Err(failure::format_err!("not found"))
    }

    pub fn search_from_xid(&self, xid: u32) -> Result<Ipv4Addr, failure::Error> {
        match self.entries.iter().find(|entry| entry.id == xid) {
            Some(entry) => Ok(entry.ip_addr),
            None => Err(failure::format_err!("not found such id({})", xid))
        }
    }

    pub fn search_from_ip(&self, addr: &Ipv4Addr) -> Result<Ipv4Addr, failure::Error>{
        for e in self.entries.iter() {
            if e.ip_addr == *addr {
                return Ok(e.ip_addr);
            }
        }
        Err(failure::format_err!("not found"))
    }

    pub fn search_from_mac(&self, addr: &MacAddr) -> Result<Ipv4Addr, failure::Error> {
        for e in self.entries.iter() {
            if e.mac_addr == *addr {
                return Ok(e.ip_addr)
            }
        }
        Err(failure::format_err!("not found"))
    }

    pub fn delete_by_ip(&mut self, ip_addr: &Ipv4Addr) -> Result<(), failure::Error> {
        let index = self.index_from_ip(ip_addr)?;
        self.entries.remove(index);
        Ok(())
    }

    pub fn find_available_address(&self, pool: Ipv4Network, mut used: Vec<Ipv4Addr>) -> Option<Ipv4Addr> {
        let mut s: Vec<Ipv4Addr> = self.entries.iter().map(|e| e.ip_addr).collect();
        s.append(&mut used);
        for addr in pool.iter() {
            if let Some(_) = s.iter().find(|u| **u == addr) {
                continue;
            } else {
                return Some(addr);
            }
        }
        None
    }


}

#[cfg(test)]
mod tests {
    #[test]
    fn test_find_available_address() {
        let mut storage = super::Storage::new();
        storage.add(&super::Entry::new(1, 
            super::Ipv4Addr::new(192,168,0,0), 
            super::MacAddr::new(1,1,1,1,1,1)));
        storage.add(
            &super::Entry::new(
                2,
                super::Ipv4Addr::new(192,168,0,2),
                super::MacAddr::new(2,2,2,2,2,2)
            ));
        let used: Vec<super::Ipv4Addr> = vec![super::Ipv4Addr::new(192,168,0,1), 
                                                super::Ipv4Addr::new(8,8,8,8)];
        let subnet = super::Ipv4Network::from_cidr("192.168.0.0/24").unwrap();
        let addr = storage.find_available_address(subnet, used).unwrap();
        assert_eq!(addr, super::Ipv4Addr::new(192,168, 0, 3));
    }

    #[test]
    fn test_update() {
        let mut storage = super::Storage::new();
        storage.add(&super::Entry::new(1, 
            super::Ipv4Addr::new(192,168,0,0), 
            super::MacAddr::new(1,1,1,1,1,1)));
        storage.add(
            &super::Entry::new(
                2,
                super::Ipv4Addr::new(192,168,0,2),
                super::MacAddr::new(2,2,2,2,2,2)
            ));
        storage.update(&super::Entry::new(
            1,
            super::Ipv4Addr::new(192,168,0,5),
            super::MacAddr::new(1,1,1,1,1,1)
        )).unwrap();
        assert_eq!(storage.search_from_xid(1).unwrap(), super::Ipv4Addr::new(192,168,0,5));
    }

    #[test]
    fn test_index() {
        let mut storage = super::Storage::new();
        storage.add(&super::Entry::new(1, 
            super::Ipv4Addr::new(192,168,0,0), 
            super::MacAddr::new(1,1,1,1,1,1)));
        storage.add(
            &super::Entry::new(
                2,
                super::Ipv4Addr::new(192,168,0,2),
                super::MacAddr::new(2,2,2,2,2,2)
            )); 
        let i = storage.index(&super::MacAddr::new(1,1,1,1,1,1)).unwrap();
        assert_eq!(i, 0);
    }
}

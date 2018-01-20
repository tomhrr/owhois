extern crate csv;
extern crate intervaltree;
extern crate ipnet;
extern crate rand;
extern crate regex;

use super::lookup::Asn;
use super::lookup::AsnRange;
use super::lookup::AsnResourceLookup;
use super::lookup::Ipv4ResourceLookup;
use super::lookup::Ipv6ResourceLookup;
use super::lookup::ResourceLookup;

use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;
use self::regex::Regex;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::iter::FromIterator;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

pub struct Context {
    pub ipv4:    Ipv4ResourceLookup,
    pub ipv6:    Ipv6ResourceLookup,
    pub asn:     AsnResourceLookup,
    pub servers: Vec<String>,
}

impl Context {
    pub fn from_files(ipv4_file: &str,
                      ipv6_file: &str,
                      asn_file: &str) -> Context {
        let files: Vec<&str> = vec![ipv4_file,ipv6_file,asn_file];
        let mut servers: HashSet<String> = HashSet::new();
        files.iter().for_each(|s| {
            let file = File::open(s).unwrap();
            let mut csv_reader = csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader(file);
            csv_reader.records()
                .filter(|i| i.is_ok())
                .for_each(|i| { servers.insert(String::from(
                                    i.unwrap().get(1).unwrap()
                                )); });
        });

        let mut reverse_servers = Vec::from_iter(servers.drain());
        reverse_servers.sort();

        let mut servers: HashMap<String, u32> = HashMap::new();
        reverse_servers.iter()
            .enumerate()
            .for_each(|(i, s)| { servers.insert(s.clone(), i as u32); });

        let file = File::open(ipv4_file).unwrap();
        let mut csv_reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(file);
        let mut ipv4_entries = Vec::new();
        csv_reader.records()
            .filter(|i| i.is_ok())
            .map(|i| i.unwrap())
            .for_each(|i| { let range  = i.get(0).unwrap();
                            let server = i.get(1).unwrap();
                            ipv4_entries.push(
                                (Ipv4Net::from_str(range).unwrap(),
                                 *(servers.get(server).unwrap()))
                            ); });

        let file = File::open(ipv6_file).unwrap();
        let mut csv_reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(file);
        let mut ipv6_entries = Vec::new();
        csv_reader.records()
            .filter(|i| i.is_ok())
            .map(|i| i.unwrap())
            .for_each(|i| { let range  = i.get(0).unwrap();
                            let server = i.get(1).unwrap();
                            ipv6_entries.push(
                                (Ipv6Net::from_str(range).unwrap(),
                                 *(servers.get(server).unwrap()))
                            ); });

        let file = File::open(asn_file).unwrap();
        let mut csv_reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(file);
        let mut asn_entries = Vec::new();
        csv_reader.records()
            .filter(|i| i.is_ok())
            .map(|i| i.unwrap())
            .for_each(|i| { let range = i.get(0).unwrap();
                            let server = i.get(1).unwrap();
                            let els: Vec<&str> = range.split("-").collect();
                            let start = u64::from_str(els.get(0).unwrap()).unwrap();
                            let end   = u64::from_str(els.get(1).unwrap()).unwrap();
                            asn_entries.push(
                                (AsnRange { start: Asn { value: start },
                                            end:   Asn { value: end + 1 } },
                                            *(servers.get(server).unwrap()))
                            ); });

        let mut final_servers = Vec::new();
        for i in reverse_servers.iter() {
            final_servers.push(i.clone());
        }

        Context {
            ipv4:    ResourceLookup::from_iter(ipv4_entries),
            ipv6:    ResourceLookup::from_iter(ipv6_entries),
            asn:     ResourceLookup::from_iter(asn_entries),
            servers: final_servers,
        }
    }

    pub fn lookup(&self, value: &str) -> Option<&String> {
        match self.lookup_internal(value) {
            Some(server_index) => {
                self.servers.get(server_index as usize)
            },
            None => {
                None
            }
        }
    }

    pub fn lookup_internal(&self, value: &str) -> Option<u32> {
        let ipv4_address_result = Ipv4Addr::from_str(value);
        if let Ok(ipv4_address) = ipv4_address_result {
            let ipv4_net = Ipv4Net::new(ipv4_address, 32).unwrap();
            return self.ipv4.get_longest_match_value(ipv4_net);
        }

        let ipv4_net_result = Ipv4Net::from_str(value);
        if let Ok(ipv4_net) = ipv4_net_result {
            return self.ipv4.get_longest_match_value(ipv4_net);
        }

        let ipv6_address_result = Ipv6Addr::from_str(value);
        if let Ok(ipv6_address) = ipv6_address_result {
            let ipv6_net = Ipv6Net::new(ipv6_address, 128).unwrap();
            return self.ipv6.get_longest_match_value(ipv6_net);
        }

        let ipv6_net_result = Ipv6Net::from_str(value);
        if let Ok(ipv6_net) = ipv6_net_result {
            return self.ipv6.get_longest_match_value(ipv6_net);
        }

        let asn_regex = Regex::new(r"^(?i)AS(\d+)$").unwrap();
        if let Some(captures) = asn_regex.captures(value) {
            if let Ok(asn_value) = u32::from_str(captures.get(1).unwrap().as_str()) {
                return self.asn.get_longest_match_value(
                    AsnRange{ start: Asn { value: asn_value as u64 },
                              end:   Asn { value: (asn_value as u64) + 1 }}
                );
            }
        }

        let asn_range_regex = Regex::new(r"^(?i)AS(\d+)\s*-AS(\d+)$").unwrap();
        if let Some(captures) = asn_range_regex.captures(value) {
            if let Ok(asn_value_start) = u32::from_str(captures.get(1).unwrap().as_str()) {
                if let Ok(asn_value_end) = u32::from_str(captures.get(2).unwrap().as_str()) {
                    return self.asn.get_longest_match_value(
                        AsnRange { start: Asn { value: asn_value_start as u64 },
                                   end:   Asn { value: asn_value_end as u64 } }
                    );
                }
            }
        }

        return None;
    }
}

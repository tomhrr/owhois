extern crate csv;
extern crate intervaltree;
extern crate ipnet;
extern crate treebitmap;

use super::super::lookup::Asn;
use super::super::lookup::AsnRange;
use super::super::lookup::AsnResourceLookup;
use super::super::lookup::Ipv4ResourceLookup;
use super::super::lookup::Ipv6ResourceLookup;
use super::super::lookup::ResourceLookup;
use super::processor::Processor;

use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;

use std::cmp::max;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

pub struct Delegated {}

fn largest_prefix_length(address: Ipv4Addr) -> u32 {
    let num = to_u32(address);
    let mut length = 8;
    while num % (u32::pow(2, 32 - length)) != 0 {
        length = length + 1;
    }
    return length;
}

fn to_prefixes(address: Ipv4Addr, hosts: u32) -> Vec<(Ipv4Addr, u8)> {
    let mut prefixes: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut current_address = address;
    let mut remaining_hosts = hosts;

    while remaining_hosts > 0 {
        let prefix_length: u32 = 32 - ((remaining_hosts as f32).log2() as u32);
        let new_prefix_length =
            max(prefix_length,
                largest_prefix_length(current_address));
        prefixes.push((current_address, new_prefix_length as u8));

        let new_hosts = u32::pow(2, 32 - new_prefix_length);
        remaining_hosts = remaining_hosts - new_hosts;

        current_address = Ipv4Addr::from(to_u32(current_address) + new_hosts);
    }

    return prefixes;
}

fn to_u32(address: Ipv4Addr) -> u32 {
    let octets = address.octets();
    let value =
        (octets[0] as u32) << 24
      | (octets[1] as u32) << 16
      | (octets[2] as u32) << 8
      | (octets[3] as u32);

    return value;
}

fn handle_ipv4<T: ResourceLookup<Ipv4Net, u32>>(
        record: &csv::StringRecord,
        server: u32,
        ipv4_lookup: &T,
        ipv4_entries: &mut Vec<(Ipv4Net, u32)>) {
    let address_str = record.get(3).unwrap();
    let size_str = record.get(4).unwrap();
    if let Ok(address) = Ipv4Addr::from_str(address_str) {
        let prefixes = to_prefixes(address, u32::from_str(size_str).unwrap());
        for &(prefix_address, prefix_length) in prefixes.iter() {
            let net = Ipv4Net::new(prefix_address, prefix_length).unwrap();
            match ipv4_lookup.get_longest_match(net) {
                Some((_, lm_server)) => {
                    if server != lm_server {
                        ipv4_entries.push((net, server));
                    }
                },
                None => {
                    ipv4_entries.push((net, server));
                },
            }
        }
    }
}

fn handle_ipv6<T: ResourceLookup<Ipv6Net, u32>>(
        record: &csv::StringRecord,
        server: u32,
        ipv6_lookup: &T,
        ipv6_entries: &mut Vec<(Ipv6Net, u32)>) {
    let address_str = record.get(3).unwrap();
    let prefix_length_str = record.get(4).unwrap();
    if let Ok(address) = Ipv6Addr::from_str(address_str) {
        let prefix_length = u8::from_str(prefix_length_str).unwrap();
        let net = Ipv6Net::new(address, prefix_length).unwrap();
        match ipv6_lookup.get_longest_match(net) {
            Some((_, lm_server)) => {
                if server != lm_server {
                    ipv6_entries.push((net, server));
                }
            },
            None => {
                ipv6_entries.push((net, server));
            },
        }
    }
}

fn handle_asn<T: ResourceLookup<AsnRange, u32>>(
        record: &csv::StringRecord,
        server: u32,
        asn_lookup: &T,
        asn_entries: &mut Vec<(AsnRange, u32)>) {

    let asn_str = record.get(3).unwrap();
    let count = record.get(4).unwrap();
    if let Ok(start_asn) = u32::from_str(asn_str) {
        let end_asn = start_asn + (u32::from_str(count).unwrap());
        let asn_range = AsnRange { start: Asn { value: start_asn },
                                   end:   Asn { value: end_asn } };
        match asn_lookup.get_longest_match(asn_range) {
            Some((_, lm_server)) => {
                if server != lm_server {
                    asn_entries.push((asn_range, server));
                }
            },
            None => {
                asn_entries.push((asn_range, server));
            },
        }
    }
}

fn parse_delegated_data<T1: ResourceLookup<Ipv4Net, u32>,
                        T2: ResourceLookup<Ipv6Net, u32>,
                        T3: ResourceLookup<AsnRange, u32>>(
        ipv4_lookup: &T1, ipv6_lookup: &T2, asn_lookup: &T3,
        server: u32, path: &str,
        ipv4_entries: &mut Vec<(Ipv4Net, u32)>,
        ipv6_entries: &mut Vec<(Ipv6Net, u32)>,
        asn_entries: &mut Vec<(AsnRange, u32)>) {
    let file = File::open(path).unwrap();
    let mut csv_reader = csv::ReaderBuilder::new()
        .delimiter(b'|')
        .flexible(true)
        .has_headers(false)
        .from_reader(file);
    csv_reader.records()
        .filter(|i| i.is_ok())
        .map(|i| i.unwrap())
        .filter(|i| i.len() > 1)
        .for_each(|i| {
            let record_type = i.get(2).unwrap();
            match record_type {
                "ipv4" => { handle_ipv4(&i, server, ipv4_lookup, ipv4_entries) },
                "ipv6" => { handle_ipv6(&i, server, ipv6_lookup, ipv6_entries) },
                "asn"  => { handle_asn( &i, server, asn_lookup,  asn_entries)  },
                _      => {},
            }
        });
}

impl Processor for Delegated {
    fn new() -> Delegated { Delegated {} }

    fn run(&self,
           directory:    &str,
           servers:      &HashMap<String, u32>,
           ipv4_lookup:  &Ipv4ResourceLookup,
           ipv6_lookup:  &Ipv6ResourceLookup,
           asn_lookup:   &AsnResourceLookup,
           ipv4_entries: &mut Vec<(Ipv4Net, u32)>,
           ipv6_entries: &mut Vec<(Ipv6Net, u32)>,
           asn_entries:  &mut Vec<(AsnRange, u32)>) {

        let afrinic_path =
            format!("{}/afrinic/delegated-afrinic-extended-latest", directory);
        parse_delegated_data(ipv4_lookup, ipv6_lookup, asn_lookup,
                             *(servers.get("whois.afrinic.net").unwrap()),
                             &afrinic_path,
                             ipv4_entries, ipv6_entries, asn_entries);
        let apnic_path =
            format!("{}/apnic/delegated-apnic-extended-latest", directory);
        parse_delegated_data(ipv4_lookup, ipv6_lookup, asn_lookup,
                             *(servers.get("whois.apnic.net").unwrap()),
                             &apnic_path,
                             ipv4_entries, ipv6_entries, asn_entries);
        let arin_path =
            format!("{}/arin/delegated-arin-extended-latest", directory);
        parse_delegated_data(ipv4_lookup, ipv6_lookup, asn_lookup,
                             *(servers.get("whois.arin.net").unwrap()),
                             &arin_path,
                             ipv4_entries, ipv6_entries, asn_entries);
        let lacnic_path =
            format!("{}/lacnic/delegated-lacnic-extended-latest", directory);
        parse_delegated_data(ipv4_lookup, ipv6_lookup, asn_lookup,
                             *(servers.get("whois.lacnic.net").unwrap()),
                             &lacnic_path,
                             ipv4_entries, ipv6_entries, asn_entries);
        let ripe_path =
            format!("{}/ripe/delegated-ripencc-extended-latest", directory);
        parse_delegated_data(ipv4_lookup, ipv6_lookup, asn_lookup,
                             *(servers.get("whois.ripe.net").unwrap()),
                             &ripe_path,
                             ipv4_entries, ipv6_entries, asn_entries);
    }
}

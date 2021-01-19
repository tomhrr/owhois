extern crate csv;
extern crate intervaltree;
extern crate ipnet;
extern crate treebitmap;

use super::super::lookup::Asn;
use super::super::lookup::AsnRange;
use super::super::lookup::AsnResourceLookup;
use super::super::lookup::Ipv4ResourceLookup;
use super::super::lookup::Ipv6ResourceLookup;
use super::processor::Processor;

use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;

use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub struct Iana {}

fn parse_ipv4_iana_data(directory: &str,
                        servers: &HashMap<String, u32>,
                        entries: &mut Vec<(Ipv4Net, u32)>) {
    let path = format!("{}/iana/ipv4-address-space.csv", directory);
    let file = File::open(path).unwrap();
    let mut csv_reader = csv::Reader::from_reader(file);
    csv_reader.records()
        .filter(|i| i.is_ok())
        .map(|i| i.unwrap())
        .for_each(|i| {
            let server = i.get(3).unwrap();
            let index = *(servers.get(server).unwrap());

            let address_str = i.get(0).unwrap();
            let address: Vec<&str> = address_str.split('/').collect();
            let first_octet   = u8::from_str(address.get(0).unwrap()).unwrap();
            let prefix_length = u32::from_str(address.get(1).unwrap()).unwrap();

            entries.push((Ipv4Net::new(Ipv4Addr::new(first_octet,0,0,0),
                                       prefix_length as u8).unwrap(),
                          index));
        });
}

fn parse_ipv6_iana_data(directory: &str,
                        servers: &HashMap<String, u32>,
                        entries: &mut Vec<(Ipv6Net, u32)>) {
    let path = format!("{}/iana/ipv6-unicast-address-assignments.csv", directory);
    let file = File::open(path).unwrap();
    let mut csv_reader = csv::Reader::from_reader(file);
    csv_reader.records()
        .filter(|i| i.is_ok())
        .map(|i| i.unwrap())
        .for_each(|i| {
            let server = i.get(3).unwrap();
            let index = *(servers.get(server).unwrap());

            let address_str = i.get(0).unwrap();
            let net = Ipv6Net::from_str(address_str).unwrap();

            entries.push((net, index));
        });
}

fn parse_asn16_iana_data(directory: &str,
                         servers: &HashMap<String, u32>,
                         entries: &mut Vec<(AsnRange, u32)>) {
    let path = format!("{}/iana/as-numbers-1.csv", directory);
    let file = File::open(path).unwrap();
    let mut csv_reader = csv::Reader::from_reader(file);
    csv_reader.records()
        .filter(|i| i.is_ok())
        .map(|i| i.unwrap())
        .for_each(|i| {
            let server = i.get(2).unwrap();
            let index  = *(servers.get(server).unwrap());

            let range = i.get(0).unwrap();
            match range.contains("-") {
                true => {
                    let nums: Vec<&str> = range.split("-").collect();
                    let start = u32::from_str(nums.get(0).unwrap()).unwrap();
                    let end   = u32::from_str(nums.get(1).unwrap()).unwrap();
                    entries.push((AsnRange { start: Asn { value: start },
                                             end:   Asn { value: end + 1 } },
                                  index));
                },
                false => {
                    let num = u32::from_str(range).unwrap();
                    entries.push((AsnRange { start: Asn { value: num },
                                             end:   Asn { value: num + 1 } },
                                  index));
                }
            }
        });
}

fn parse_asn32_iana_data(directory: &str,
                         servers: &HashMap<String, u32>,
                         entries: &mut Vec<(AsnRange, u32)>) {
    let path = format!("{}/iana/as-numbers-2.csv", directory);
    let file = File::open(path).unwrap();
    let mut csv_reader = csv::Reader::from_reader(file);
    csv_reader.records()
        .filter(|i| i.is_ok())
        .map(|i| i.unwrap())
        .for_each(|i| {
            let server = i.get(2).unwrap();
            let index  = *(servers.get(server).unwrap());

            let range = i.get(0).unwrap();
            match range.contains("-") {
                true => {
                    let nums: Vec<&str> = range.split("-").collect();
                    let start = u32::from_str(nums.get(0).unwrap()).unwrap();
                    let end   = u32::from_str(nums.get(1).unwrap()).unwrap();
                    if start >= 65536 {
                        entries.push((AsnRange { start: Asn { value: start },
                                                 end:   Asn { value: end + 1 } },
                                      index));
                    }
                },
                false => {
                    let num = u32::from_str(range).unwrap();
                    if num >= 65536 {
                        entries.push((AsnRange { start: Asn { value: num },
                                                 end:   Asn { value: num.wrapping_add(1) } },
                                      index));
                    }
                }
            }
        });
}

impl Processor for Iana {
    fn new() -> Iana { Iana {} }
    fn run(&self,
           directory:    &str,
           servers:      &HashMap<String, u32>,
           _ipv4_lookup:  &Ipv4ResourceLookup,
           _ipv6_lookup:  &Ipv6ResourceLookup,
           _asn_lookup:   &AsnResourceLookup,
           ipv4_entries: &mut Vec<(Ipv4Net, u32)>,
           ipv6_entries: &mut Vec<(Ipv6Net, u32)>,
           asn_entries:  &mut Vec<(AsnRange, u32)>) {
        parse_ipv4_iana_data(directory, servers, ipv4_entries);
        parse_ipv6_iana_data(directory, servers, ipv6_entries);
        parse_asn16_iana_data(directory, servers, asn_entries);
        parse_asn32_iana_data(directory, servers, asn_entries);
    }
}

pub mod iana;
pub mod delegated;
pub mod processor;

extern crate csv;
extern crate intervaltree;
extern crate ipnet;
extern crate treebitmap;

use super::lookup::AsnRange;
use super::lookup::AsnResourceLookup;
use super::lookup::Ipv4ResourceLookup;
use super::lookup::Ipv6ResourceLookup;
use super::lookup::ResourceLookup;

use self::delegated::Delegated;
use self::iana::Iana;
use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;
use self::processor::Processor;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::iter::FromIterator;
use std::str::FromStr;

fn run_processors(directory:  &str,
                  servers:    &HashMap<String, u32>,
                  processors: Vec<Box<dyn Processor>>,
                  ipv4_path:  &str,
                  ipv6_path:  &str,
                  asn_path:   &str) {
    let mut ipv4_entries: Vec<(Ipv4Net, u32)>  = Vec::new();
    let mut ipv6_entries: Vec<(Ipv6Net, u32)>  = Vec::new();
    let mut asn_entries:  Vec<(AsnRange, u32)> = Vec::new();

    for processor in processors.iter() {
        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(ipv4_entries.clone());
        let ipv6_lookup: Ipv6ResourceLookup =
            ResourceLookup::from_iter(ipv6_entries.clone());
        let asn_lookup:  AsnResourceLookup =
            ResourceLookup::from_iter(asn_entries.clone());

        processor.run(directory, servers, &ipv4_lookup,
                      &ipv6_lookup, &asn_lookup,
                      &mut ipv4_entries, &mut ipv6_entries,
                      &mut asn_entries);
    }

    let mut reverse_servers = Vec::from_iter(servers.keys());
    reverse_servers.sort();
    let get_reverse_server = |i| {
        reverse_servers.get(i as usize).unwrap()
    };

    let mut output_file = File::create(ipv4_path).unwrap();
    ipv4_entries.iter().for_each(|&(ipv4_net, index)| {
        let line = format!("{},{}\n", ipv4_net, get_reverse_server(index));
        output_file.write_all(line.as_bytes()).unwrap();
    });

    let mut output_file = File::create(ipv6_path).unwrap();
    ipv6_entries.iter().for_each(|&(ipv6_net, index)| {
        let line = format!("{},{}\n", ipv6_net, get_reverse_server(index));
        output_file.write_all(line.as_bytes()).unwrap();
    });

    let mut output_file = File::create(asn_path).unwrap();
    asn_entries.iter().for_each(|&(ref asn_range, index)| {
        /* Account for overflow in the last ASN. */
        let final_asn =
            if asn_range.end.value == 0 {
                4294967295
            } else {
                asn_range.end.value - 1
            };
        let line = format!("{}-{},{}\n",
                           asn_range.start.value,
                           final_asn,
                           get_reverse_server(index));
        output_file.write_all(line.as_bytes()).unwrap();
    });
}

pub fn process_public(public_data_dir: &str,
                      ipv4_path: &str,
                      ipv6_path: &str,
                      asn_path: &str) {
    let mut servers: HashMap<String, u32> = HashMap::new();
    servers.insert(String::from_str("").unwrap(),                  0);
    servers.insert(String::from_str("whois.afrinic.net").unwrap(), 1);
    servers.insert(String::from_str("whois.apnic.net").unwrap(),   2);
    servers.insert(String::from_str("whois.arin.net").unwrap(),    3);
    servers.insert(String::from_str("whois.iana.org").unwrap(),    4);
    servers.insert(String::from_str("whois.lacnic.net").unwrap(),  5);
    servers.insert(String::from_str("whois.ripe.net").unwrap(),    6);
    run_processors(public_data_dir, &servers,
                   vec![Box::new(Iana::new()),
                        Box::new(Delegated::new())],
                   ipv4_path, ipv6_path, asn_path);
}

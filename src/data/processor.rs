extern crate ipnet;

use super::super::lookup::AsnRange;
use super::super::lookup::AsnResourceLookup;
use super::super::lookup::Ipv4ResourceLookup;
use super::super::lookup::Ipv6ResourceLookup;

use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;

use std::collections::HashMap;

pub trait Processor {
    fn new() -> Self where Self: Sized;
    fn run(&self,
           directory:    &str,
           servers:      &HashMap<String, u32>,
           ipv4_lookup:  &Ipv4ResourceLookup,
           ipv6_lookup:  &Ipv6ResourceLookup,
           asn_lookup:   &AsnResourceLookup,
           ipv4_entries: &mut Vec<(Ipv4Net, u32)>,
           ipv6_entries: &mut Vec<(Ipv6Net, u32)>,
           asn_entries:  &mut Vec<(AsnRange, u32)>);
}

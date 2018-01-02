extern crate csv;
extern crate intervaltree;
extern crate ipnet;
extern crate treebitmap;

use self::intervaltree::IntervalTree;
use self::ipnet::Contains;
use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;
use self::treebitmap::IpLookupTable;
use self::treebitmap::IpLookupTableOps;

use std::iter::FromIterator;
use std::iter::Iterator;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ops::Add;
use std::ops::Range;
use std::ops::Sub;

pub trait ResourceLookup<K, V> {
    fn from_iter<I>(values: I) -> Self
        where I: IntoIterator<Item = (K, V)>;
    fn get_longest_match(&self, value: K) -> Option<(Option<K>, V)>;
    fn get_longest_match_value(&self, value: K) -> Option<V>;
}

macro_rules! impl_ip_lookup {
    ($addr_type: ident, $net_type: ident) => {
        impl ResourceLookup<$net_type, u32>
                for IpLookupTable<$addr_type, (Option<$net_type>, u32)> {
            /* todo: ugh. */
            fn get_longest_match(&self, net: $net_type)
                    -> Option<(Option<$net_type>, u32)> {
                match IpLookupTable::longest_match(self, net.addr()) {
                    Some((address, length, &entry)) => {
                        let found_net = $net_type::new(address, (length as u8)).unwrap();
                        match found_net.contains(&net) {
                            true => { Some((Some(found_net), entry.1)) }
                            _    => {
                                match entry {
                                    (Some(parent_net), _) => {
                                        let mut current_net = parent_net;
                                        while !current_net.contains(&net) {
                                            match IpLookupTable::exact_match(
                                                self,
                                                current_net.addr(),
                                                current_net.prefix_len() as u32
                                            ) {
                                                Some(&(Some(new_net), _)) => {
                                                    current_net = new_net;
                                                }
                                                _ => {
                                                    return None;
                                                }
                                            }
                                        }
                                        let current_index;
                                        match IpLookupTable::exact_match(
                                            self,
                                            current_net.addr(),
                                            current_net.prefix_len() as u32
                                        ) {
                                            Some(&(_, index)) => {
                                                current_index = index;
                                            }
                                            _ => {
                                                return None;
                                            }
                                        }
                                        return Some((Some(current_net), current_index));
                                    },
                                    _ => {
                                        None
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        None
                    }
                }
            }

            fn get_longest_match_value(&self, net: $net_type) -> Option<u32> {
                match self.get_longest_match(net) {
                    Some((_, value)) => Some(value),
                    _                => None
                }
            }

            fn from_iter<I: IntoIterator<Item=($net_type, u32)>>(values: I)
                    -> IpLookupTable<$addr_type, (Option<$net_type>, u32)> {
                let mut ip_lookup_table = IpLookupTable::new();
                for (net, value) in values {
                    let parent_match =
                        ResourceLookup::get_longest_match(&ip_lookup_table, net);
                    let parent = match parent_match { Some((v, _)) => v, _ => None };
                    ip_lookup_table.insert(net.addr(),
                                           (net.prefix_len() as u32),
                                           (parent, value));
                }
                ip_lookup_table
            }
        }
    }
}

impl_ip_lookup!(Ipv4Addr, Ipv4Net);
impl_ip_lookup!(Ipv6Addr, Ipv6Net);

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub struct Asn {
    pub value: u64
}

impl Add for Asn {
    type Output = Asn;
    fn add(self, other: Asn) -> Asn {
        Asn { value: self.value + other.value }
    }
}

impl Sub for Asn {
    type Output = Asn;
    fn sub(self, other: Asn) -> Asn {
        Asn { value: self.value - other.value }
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub struct AsnRange {
    pub start: Asn,
    pub end: Asn,
}

impl ResourceLookup<AsnRange, u32>
        for IntervalTree<Asn, u32> {
    fn get_longest_match(&self, asrange: AsnRange)
            -> Option<(Option<AsnRange>, u32)> {
        let difference = (asrange.end.value - 1) - asrange.start.value;
        let iter =
            match difference == 0 {
                true  => IntervalTree::query_point(self, asrange.start),
                false => IntervalTree::query(self, Range {
                                                    start: asrange.start,
                                                    end: asrange.end
                                                   })
            };
        let mut response: Vec<_> =
            iter.map(|i| { (AsnRange { start: i.range.start,
                                       end:   i.range.end },
                            i.value) })
                .filter(|i| { (i.0.start <= asrange.start)
                           && (i.0.end   >= asrange.end) })
                .collect();
        response.sort_by(|a, b| { let a_diff = a.0.end - a.0.start;
                                  let b_diff = b.0.end - b.0.start;
                                  a_diff.cmp(&b_diff) });
        match response.len() >= 1 {
            true => { Some((Some(response.get(0).unwrap().0),
                            response.get(0).unwrap().1)) }
            false => None
        }
    }

    fn get_longest_match_value(&self, asrange: AsnRange)
            -> Option<u32> {
        match self.get_longest_match(asrange) {
            Some((_, value)) => Some(value),
            _                => None
        }
    }

    fn from_iter<I: IntoIterator<Item=(AsnRange, u32)>>(values: I)
            -> IntervalTree<Asn, u32> {
        FromIterator::from_iter(
            values.into_iter()
                .map(|(r, v)| { (Range { start: r.start, end: r.end }, v)})
        )
    }
}

pub type Ipv4ResourceLookup = IpLookupTable<Ipv4Addr, (Option<Ipv4Net>, u32)>;
pub type Ipv6ResourceLookup = IpLookupTable<Ipv6Addr, (Option<Ipv6Net>, u32)>;
pub type AsnResourceLookup  = IntervalTree<Asn, u32>;

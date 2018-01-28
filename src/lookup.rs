extern crate csv;
extern crate intervaltree;
extern crate ipnet;
extern crate treebitmap;
extern crate time;

use self::intervaltree::IntervalTree;
use self::ipnet::Ipv4Net;
use self::ipnet::Ipv6Net;
use self::ipnet::Emu128;

use std::iter::FromIterator;
use std::iter::Iterator;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ops::Add;
use std::ops::Range;
use std::ops::Shr;
use std::ops::Sub;

pub trait ResourceLookup<K, V> {
    fn from_iter<I>(values: I) -> Self
        where I: IntoIterator<Item = (K, V)>;
    fn get_longest_match(&self, value: K) -> Option<(Option<K>, V)>;
    fn get_longest_match_value(&self, value: K) -> Option<V>;
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

fn ipv4_increment(address: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(to_u32(address).wrapping_add(1))
}

fn ipv6_increment(address: Ipv6Addr) -> Ipv6Addr {
    let as_num = Emu128::from(address);
    if as_num == Emu128::max_value() {
        Emu128::min_value().into()
    } else {
        as_num.saturating_add(Emu128::from(1)).into()
    }
}

fn ipv6_decrement(address: Ipv6Addr) -> Ipv6Addr {
    let as_num = Emu128::from(address);
    if as_num == Emu128::min_value() {
        Emu128::max_value().into()
    } else {
        as_num.saturating_sub(Emu128::from(1)).into()
    }
}

pub struct Ipv4IntervalTree {
    interval_tree: IntervalTree<Ipv4Addr, u32>,
    last_values:   Vec<(Range<Ipv4Addr>, u32)>,
}

impl ResourceLookup<Ipv4Net, u32>
        for Ipv4IntervalTree {
    fn get_longest_match(&self, net: Ipv4Net)
            -> Option<(Option<Ipv4Net>, u32)> {
        let range_end = ipv4_increment(net.broadcast());
        let iter =
            match net.prefix_len() == net.max_prefix_len() {
                true  => IntervalTree::query_point(&self.interval_tree, net.addr()),
                false => IntervalTree::query(&self.interval_tree, Range {
                                                       start: net.addr(),
                                                       end:   range_end
                                                   })
            };
        let mut matching_last_values: Vec<(Range<Ipv4Addr>, u32)> =
            self.last_values.iter().filter(|v| {
                v.0.start <= net.addr()
            }).map(|v| { v.clone() }).collect();
        let mut response: Vec<(Range<Ipv4Addr>, u32)> =
            iter.filter(|i| {  (i.range.start <= net.addr())
                            && (to_u32(i.range.end).wrapping_sub(1) >= to_u32(net.broadcast())) })
                .map(|i| { (Range { start: i.range.start,
                                    end: i.range.end }, i.value) })
                .collect();
        response.append(&mut matching_last_values);
        response.sort_by(
            |a, b| { let a_size = to_u32(a.0.end).wrapping_sub(to_u32(a.0.start));
                     let b_size = to_u32(b.0.end).wrapping_sub(to_u32(b.0.start));
                     a_size.cmp(&b_size) }
        );

        match response.len() >= 1 {
            true => {
                let entry = response.get(0).unwrap();
                let range = &entry.0;
                let host_count = to_u32(range.end).wrapping_sub(to_u32(range.start));
                let prefix_length: u32 = 32 - ((host_count as f32).log2() as u32);

                Some((Some(Ipv4Net::new(range.start, prefix_length as u8).unwrap()),
                     entry.1))
            },
            false => None
        }
    }

    fn get_longest_match_value(&self, net: Ipv4Net)
            -> Option<u32> {
        match self.get_longest_match(net) {
            Some((_, value)) => Some(value),
            _                => None
        }
    }

    fn from_iter<I: IntoIterator<Item=(Ipv4Net, u32)>>(values: I)
            -> Ipv4IntervalTree  {
        let interval_tree: IntervalTree<Ipv4Addr, u32> =
            FromIterator::from_iter(
                values.into_iter()
                    .map(|(r, v)| {
                        (Range { start: r.addr(),
                                 end:   ipv4_increment(r.broadcast()) }, v)})
            );
        Ipv4IntervalTree {
            last_values:
                interval_tree.iter()
                    .filter(|v| { v.range.end == Ipv4Addr::new(0, 0, 0, 0) })
                    .map(|v| { (Range { start: v.range.start,
                                        end: v.range.end }, v.value) })
                    .collect(),
            interval_tree: interval_tree,
        }
    }
}

pub struct Ipv6IntervalTree {
    interval_tree: IntervalTree<Ipv6Addr, u32>,
    last_values:   Vec<(Range<Ipv6Addr>, u32)>,
}

impl ResourceLookup<Ipv6Net, u32>
        for Ipv6IntervalTree {
    fn get_longest_match(&self, net: Ipv6Net)
            -> Option<(Option<Ipv6Net>, u32)> {
        let range_end = ipv6_increment(net.broadcast());
        let iter =
            match net.prefix_len() == net.max_prefix_len() {
                true  => IntervalTree::query_point(&self.interval_tree, net.addr()),
                false => IntervalTree::query(&self.interval_tree, Range {
                                                       start: net.addr(),
                                                       end:   range_end
                                                   })
            };

        let mut matching_last_values: Vec<(Range<Ipv6Addr>, u32)> =
            self.last_values.iter().filter(|v| {
                v.0.start <= net.addr()
            }).map(|v| { v.clone() }).collect();
        eprintln!("{:?} -> {:?}", net, matching_last_values);

        let mut response: Vec<(Range<Ipv6Addr>, u32)> =
            iter.filter(|i| { (i.range.start <= net.addr())
                           &&
                            (ipv6_decrement(i.range.end) >=
                            net.broadcast()) })
                .map(|i| { (Range { start: i.range.start,
                                    end: i.range.end }, i.value) })
                .collect();
        response.append(&mut matching_last_values);
        response.sort_by(
            |a, b| { let a_start = Emu128::from(a.0.start);
                     let a_end   = Emu128::from(ipv6_decrement(a.0.end));
                     let a_size  = a_end.saturating_sub(a_start);
                     let b_start = Emu128::from(b.0.start);
                     let b_end   = Emu128::from(ipv6_decrement(b.0.end));
                     let b_size  = b_end.saturating_sub(b_start);
                     a_size.cmp(&b_size) }
        );

        match response.len() >= 1 {
            true => {
                let entry = response.get(0).unwrap();
                let range = &entry.0;
                let start = Emu128::from(range.start);
                let end   = Emu128::from(range.start);

                let mut host_count    = end.saturating_sub(start);
                let mut prefix_length = 0;
                while host_count != Emu128::from(0) {
                    host_count = host_count.shr(1);
                    prefix_length += 1;
                }

                Some((Some(Ipv6Net::new(range.start, prefix_length as u8).unwrap()),
                     entry.1))
            },
            false => None
        }
    }

    fn get_longest_match_value(&self, net: Ipv6Net)
            -> Option<u32> {
        match self.get_longest_match(net) {
            Some((_, value)) => Some(value),
            _                => None
        }
    }

    fn from_iter<I: IntoIterator<Item=(Ipv6Net, u32)>>(values: I)
            -> Ipv6IntervalTree {
        let interval_tree: IntervalTree<Ipv6Addr, u32> =
            FromIterator::from_iter(
                values.into_iter()
                    .map(|(r, v)| {
                        (Range { start: r.addr(),
                                 end:   ipv6_increment(r.broadcast()) }, v)
                    })
            );
        Ipv6IntervalTree {
            last_values:
                interval_tree.iter()
                    .filter(|v| { v.range.end == Ipv6Addr::new(0, 0,
                    0, 0, 0, 0, 0, 0
                    ) })
                    .map(|v| { (Range { start: v.range.start,
                                        end: v.range.end }, v.value) })
                    .collect(),
            interval_tree: interval_tree,
        }
    }
}

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

pub type Ipv4ResourceLookup = Ipv4IntervalTree;
pub type Ipv6ResourceLookup = Ipv6IntervalTree;
pub type AsnResourceLookup  = IntervalTree<Asn, u32>;

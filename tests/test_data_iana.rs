extern crate owhois;
extern crate ipnet;
extern crate treebitmap;
extern crate intervaltree;

#[cfg(test)]
mod test_data_iana {
    use owhois::data::iana::Iana;
    use ipnet::Ipv4Net;
    use ipnet::Ipv6Net;
    use owhois::data::processor::Processor;
    use owhois::lookup::ResourceLookup;
    use owhois::lookup::AsnRange;
    use owhois::lookup::Asn;
    use std::str::FromStr;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::collections::HashMap;
    use treebitmap::IpLookupTable;
    use intervaltree::IntervalTree;

    #[test]
    fn iana() {
        let iana = Iana::new();
        let mut servers: HashMap<String, u32> = HashMap::new();
        servers.insert(String::from_str("").unwrap(),                  0);
        servers.insert(String::from_str("whois.afrinic.net").unwrap(), 1);
        servers.insert(String::from_str("whois.apnic.net").unwrap(),   2);
        servers.insert(String::from_str("whois.arin.net").unwrap(),    3);
        servers.insert(String::from_str("whois.iana.org").unwrap(),    4);
        servers.insert(String::from_str("whois.lacnic.net").unwrap(),  5);
        servers.insert(String::from_str("whois.ripe.net").unwrap(),    6);

        let mut ipv4_entries: Vec<(Ipv4Net, u32)> = Vec::new();
        let mut ipv6_entries: Vec<(Ipv6Net, u32)> = Vec::new();
        let mut asn_entries:  Vec<(AsnRange, u32)> = Vec::new();

        let ipv4_lookup: IpLookupTable<Ipv4Addr, (Option<Ipv4Net>, u32)> =
            ResourceLookup::from_iter(ipv4_entries.clone());
        let ipv6_lookup: IpLookupTable<Ipv6Addr, (Option<Ipv6Net>, u32)> =
            ResourceLookup::from_iter(ipv6_entries.clone());
        let asn_lookup:  IntervalTree<Asn, u32> =
            ResourceLookup::from_iter(asn_entries.clone());

        iana.run("testdata/test_data_iana", &servers,
                 &ipv4_lookup, &ipv6_lookup, &asn_lookup,
                 &mut ipv4_entries, &mut ipv6_entries, &mut asn_entries);

        let check = (Ipv4Net::from_str("0.0.0.0/8").unwrap(), 0);
        assert_eq!(ipv4_entries.get(0).unwrap(), &check);

        let check = (Ipv6Net::from_str("2001:0200::/23").unwrap(), 2);
        assert_eq!(ipv6_entries.get(1).unwrap(), &check);

        let check = (AsnRange { start: Asn { value: 7 },
                                end:   Asn { value: 8 } }, 6);
        assert_eq!(asn_entries.get(2).unwrap(), &check);
    }
}

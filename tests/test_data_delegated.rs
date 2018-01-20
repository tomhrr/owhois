extern crate owhois;
extern crate ipnet;
extern crate treebitmap;
extern crate intervaltree;

#[cfg(test)]
mod test_data_delegated {
    use owhois::data::delegated::Delegated;
    use ipnet::Ipv4Net;
    use ipnet::Ipv6Net;
    use owhois::data::processor::Processor;
    use owhois::lookup::ResourceLookup;
    use owhois::lookup::Ipv4ResourceLookup;
    use owhois::lookup::Ipv6ResourceLookup;
    use owhois::lookup::AsnResourceLookup;
    use owhois::lookup::AsnRange;
    use owhois::lookup::Asn;
    use std::str::FromStr;
    use std::collections::HashMap;

    #[test]
    fn delegated() {
        let delegated = Delegated::new();
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

        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(ipv4_entries.clone());
        let ipv6_lookup: Ipv6ResourceLookup =
            ResourceLookup::from_iter(ipv6_entries.clone());
        let asn_lookup:  AsnResourceLookup =
            ResourceLookup::from_iter(asn_entries.clone());

        delegated.run("testdata/test_data_delegated", &servers,
                 &ipv4_lookup, &ipv6_lookup, &asn_lookup,
                 &mut ipv4_entries, &mut ipv6_entries, &mut asn_entries);

        let check = (Ipv4Net::from_str("41.0.0.0/11").unwrap(), 1);
        assert_eq!(ipv4_entries.get(0).unwrap(), &check);

        let check = (Ipv6Net::from_str("2001:4201::/32").unwrap(), 1);
        assert_eq!(ipv6_entries.get(1).unwrap(), &check);

        let check = (AsnRange { start: Asn { value: 1230 },
                                end:   Asn { value: 1231 } }, 1);
        assert_eq!(asn_entries.get(2).unwrap(), &check);
    }
}

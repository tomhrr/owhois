extern crate owhois;
extern crate ipnet;

#[cfg(test)]
mod test_lookup {
    use ipnet::Ipv6Net;
    use owhois::lookup::ResourceLookup;
    use owhois::lookup::Ipv6ResourceLookup;
    use std::str::FromStr;

    #[test]
    fn ipv6_lookup_empty() {
        let ipv6_lookup: Ipv6ResourceLookup =
            ResourceLookup::from_iter(vec![]);
        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/128").unwrap()
        );
        assert_eq!(value, None);
    }

    #[test]
    fn ipv6_lookup_single() {
        let ipv6_lookup: Ipv6ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv6Net::from_str("::/128").unwrap(), 1)
            ]);
        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/128").unwrap()
        );
        assert_eq!(value, Some(1));
    }

    #[test]
    fn ipv6_lookup_multiple() {
        let ipv6_lookup: Ipv6ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv6Net::from_str("::/128").unwrap(), 1),
                (Ipv6Net::from_str("::1/128").unwrap(), 2)
            ]);
        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/128").unwrap()
        );
        assert_eq!(value, Some(1));
    }

    #[test]
    fn ipv6_lookup_parents() {
        let ipv6_lookup: Ipv6ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv6Net::from_str("::/16").unwrap(),  1),
                (Ipv6Net::from_str("::/32").unwrap(), 2),
                (Ipv6Net::from_str("::/48").unwrap(), 3),
            ]);
        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/48").unwrap()
        );
        assert_eq!(value, Some(3));

        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/32").unwrap()
        );
        assert_eq!(value, Some(2));

        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/16").unwrap()
        );
        assert_eq!(value, Some(1));

        let value = ipv6_lookup.get_longest_match_value(
            Ipv6Net::from_str("::/15").unwrap()
        );
        assert_eq!(value, None);
    }
}

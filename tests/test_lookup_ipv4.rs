extern crate owhois;
extern crate ipnet;

#[cfg(test)]
mod test_lookup {
    use ipnet::Ipv4Net;
    use owhois::lookup::ResourceLookup;
    use owhois::lookup::Ipv4ResourceLookup;
    use std::str::FromStr;

    #[test]
    fn ipv4_lookup_empty() {
        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(vec![]);
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("1.0.0.0/32").unwrap()
        );
        assert_eq!(value, None);
    }

    #[test]
    fn ipv4_lookup_single() {
        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv4Net::from_str("1.0.0.0/32").unwrap(), 1)
            ]);
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("1.0.0.0/32").unwrap()
        );
        assert_eq!(value, Some(1));
    }

    #[test]
    fn ipv4_lookup_multiple() {
        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv4Net::from_str("1.0.0.0/32").unwrap(), 1),
                (Ipv4Net::from_str("2.0.0.0/32").unwrap(), 2)
            ]);
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("1.0.0.0/32").unwrap()
        );
        assert_eq!(value, Some(1));
    }

    #[test]
    fn ipv4_lookup_parents() {
        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv4Net::from_str("2.0.0.0/8").unwrap(),  1),
                (Ipv4Net::from_str("2.0.0.0/16").unwrap(), 2),
                (Ipv4Net::from_str("2.0.0.0/32").unwrap(), 3),
            ]);
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("2.0.0.0/32").unwrap()
        );
        assert_eq!(value, Some(3));

        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("2.0.0.0/31").unwrap()
        );
        assert_eq!(value, Some(2));

        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("2.0.0.0/9").unwrap()
        );
        assert_eq!(value, Some(1));

        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("2.0.0.0/7").unwrap()
        );
        assert_eq!(value, None);
    }

    #[test]
    fn ipv4_lookup_bounds() {
        let ipv4_lookup: Ipv4ResourceLookup =
            ResourceLookup::from_iter(vec![
                (Ipv4Net::from_str("0.0.0.0/32").unwrap(), 1),
                (Ipv4Net::from_str("0.0.0.0/8").unwrap(), 2),
                (Ipv4Net::from_str("255.0.0.0/8").unwrap(), 3),
                (Ipv4Net::from_str("255.255.255.255/32").unwrap(), 4),
            ]);
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("0.0.0.0/32").unwrap()
        );
        assert_eq!(value, Some(1));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("0.0.0.1/32").unwrap()
        );
        assert_eq!(value, Some(2));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("0.0.0.0/31").unwrap()
        );
        assert_eq!(value, Some(2));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("0.0.0.0/8").unwrap()
        );
        assert_eq!(value, Some(2));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("0.0.0.0/7").unwrap()
        );
        assert_eq!(value, None);

        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("255.255.255.255/32").unwrap()
        );
        assert_eq!(value, Some(4));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("255.255.255.254/32").unwrap()
        );
        assert_eq!(value, Some(3));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("255.255.255.254/31").unwrap()
        );
        assert_eq!(value, Some(3));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("255.0.0.0/8").unwrap()
        );
        assert_eq!(value, Some(3));
        let value = ipv4_lookup.get_longest_match_value(
            Ipv4Net::from_str("254.0.0.0/7").unwrap()
        );
        assert_eq!(value, None);
    }
}

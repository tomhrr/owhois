extern crate owhois;

#[cfg(test)]
mod test_lookup {
    use owhois::lookup::ResourceLookup;
    use owhois::lookup::AsnResourceLookup;
    use owhois::lookup::Asn;
    use owhois::lookup::AsnRange;

    #[test]
    fn asn_lookup_empty() {
        let asn_lookup: AsnResourceLookup =
            ResourceLookup::from_iter(vec![]);
        let value = asn_lookup.get_longest_match_value(
            AsnRange { start: Asn { value: 1 },
                       end:   Asn { value: 2 } }
        );
        assert_eq!(value, None);
    }

    #[test]
    fn asn_lookup_single() {
        let asn_lookup: AsnResourceLookup =
            ResourceLookup::from_iter(vec![
                (AsnRange { start: Asn { value: 1 },
                            end:   Asn { value: 2 } }, 1)
            ]);
        let value = asn_lookup.get_longest_match_value(
            AsnRange { start: Asn { value: 1 },
                       end:   Asn { value: 2 } }
        );
        assert_eq!(value, Some(1));
    }

    #[test]
    fn asn_lookup_multiple() {
        let asn_lookup: AsnResourceLookup =
            ResourceLookup::from_iter(vec![
                (AsnRange { start: Asn { value: 1 },
                            end:   Asn { value: 2 } }, 1),
                (AsnRange { start: Asn { value: 2 },
                            end:   Asn { value: 3 } }, 2),
            ]);
        let value = asn_lookup.get_longest_match_value(
            AsnRange { start: Asn { value: 1 },
                       end:   Asn { value: 2 } }
        );
        assert_eq!(value, Some(1));
    }

    #[test]
    fn asn_lookup_parents() {
        let asn_lookup: AsnResourceLookup =
            ResourceLookup::from_iter(vec![
                (AsnRange { start: Asn { value: 1 },
                            end:   Asn { value: 6 } }, 1),
                (AsnRange { start: Asn { value: 2 },
                            end:   Asn { value: 5 } }, 2),
                (AsnRange { start: Asn { value: 3 },
                            end:   Asn { value: 4 } }, 3),
            ]);
        let value = asn_lookup.get_longest_match_value(
            AsnRange { start: Asn { value: 3 },
                       end:   Asn { value: 4 } }
        );
        assert_eq!(value, Some(3));

        let value = asn_lookup.get_longest_match_value(
            AsnRange { start: Asn { value: 3 },
                       end:   Asn { value: 5 } }
        );
        assert_eq!(value, Some(2));

        let value = asn_lookup.get_longest_match_value(
            AsnRange { start: Asn { value: 3 },
                       end:   Asn { value: 6 } }
        );
        assert_eq!(value, Some(1));
    }
}

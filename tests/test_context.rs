extern crate owhois;

#[cfg(test)]
mod test_context {
    use owhois::context::Context;
    use std::str::FromStr;

    #[test]
    fn context() {
        let context =
            Context::from_files(
                "testdata/test_lookup/ipv4_data_1",
                "testdata/test_lookup/ipv6_data_1",
                "testdata/test_lookup/asn_data_1",
            );

        let s1: String = String::from_str("first-server").unwrap();
        let s2: String = String::from_str("second-server").unwrap();
        let s3: String = String::from_str("third-server").unwrap();

        let value = context.lookup("asdf");
        assert_eq!(value, None);

        let value = context.lookup("1.0.0.0");
        assert_eq!(value, Some(&s1));

        let value = context.lookup("2.0.0.0/16");
        assert_eq!(value, Some(&s2));

        let value = context.lookup("4.0.0.0/8");
        assert_eq!(value, None);

        let value = context.lookup("0002::/32");
        assert_eq!(value, Some(&s2));

        let value = context.lookup("::1");
        assert_eq!(value, None);

        let value = context.lookup("AS500");
        assert_eq!(value, Some(&s1));

        let value = context.lookup("AS500-AS2500");
        assert_eq!(value, None);

        let value = context.lookup("AS2500-AS2600");
        assert_eq!(value, Some(&s3));
    }
}

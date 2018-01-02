extern crate owhois;

fn main() {
    owhois::data::process_public(
        "data",
        "data/ipv4",
        "data/ipv6",
        "data/asn"
    );
}

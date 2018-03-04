## owhois

[![Build Status](https://travis-ci.org/tomhrr/owhois.png)](https://travis-ci.org/tomhrr/owhois)

owhois is a Whois proxy server for IP address and ASN queries.  It
supports the following types of queries:

   * single IP addresses (e.g. 192.0.2.0)
   * IP address prefixes (e.g. 192.0.2.0/24)
   * single ASNs (e.g. AS64496)
   * ASN ranges (e.g. AS64496-AS64511)

### Build

    # Locally.
    $ cargo build --release

    # With Docker.
    $ docker build -t owhois .

### Usage

    # Locally.
    $ mkdir data
    $ ./get-public-data
    $ ./target/release/process-public-data
    $ RUST_LOG=info ./target/release/owhois

    # With Docker.
    $ mkdir data
    $ docker run -it -v $(pwd)/data:/data owhois /bin/sh
    / # get-public-data
    / # process-public-data
    / # exit
    $ docker run -v $(pwd)/data:/data -p 4343:4343 -e RUST_LOG=info owhois

    # With Docker (Docker Hub).
    $ docker pull tomhrr/owhois:latest
    $ mkdir data
    $ docker run -it -v $(pwd)/data:/data tomhrr/owhois:latest /bin/sh
    / # get-public-data
    / # process-public-data
    / # exit
    $ docker run -v $(pwd)/data:/data -p 4343:4343 -e RUST_LOG=info tomhrr/owhois:latest

    # With Helm.  By default, this will refresh the address data once
    # per day.
    $ cd chart/owhois
    $ helm package owhois
    $ helm install owhois

    # Example client usage.
    $ whois -hlocalhost -p4343 1.0.0.0/8

### Configuration

The mapping from IP/ASN to server is configured via CSV files with the
names `data/ipv4`, `data/ipv6`, and `data/asn`, relative to the
directory of server execution.  These files must be generated before
running the server.  Each contains IP address prefixes or ASN ranges
in the first column and server names in the second column (single IP
addresses and ASNs are not supported within these files).  CSV headers
should not be included in these files.

The `Usage` instructions above generate CSV files based on the
delegation data published by IANA and the RIRs, mapping to their Whois
servers as appropriate.

The server monitors the mapping data files for changes.  If changes
are detected, then the server reloads the mapping data.

By default, queries that are not handled by the server will be passed
through to `whois.iana.org`.  To change the server used for these
cases, pass the `--default-server` command line option when starting
the server.

### Bugs/problems/suggestions

See the [GitHub issue tracker](https://github.com/tomhrr/owhois/issues).

### Licence

See LICENCE.

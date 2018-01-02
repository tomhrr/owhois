extern crate futures;
extern crate ipnet;
extern crate time;
extern crate tokio_core;
extern crate tokio_dns;
extern crate tokio_io;

use super::context::Context;
use super::lookup::ResourceLookup;

use self::futures::{Future, Stream, Poll};
use self::ipnet::Ipv4Net;
use self::tokio_core::net::{TcpListener, TcpStream};
use self::tokio_core::reactor::Core;
use self::tokio_dns::tcp_connect;
use self::tokio_io::{AsyncRead, AsyncWrite};
use self::tokio_io::io::{copy, shutdown, lines, write_all};

use std::io::{self, Read, Write, BufReader};
use std::net::{Shutdown};
use std::str::FromStr;
use std::sync::Arc;

pub fn run(context: &'static Context,
           default_server_option: Option<String>,
           port_option: Option<String>) {
    let default_server =
        match default_server_option {
            Some(hostname) => hostname,
            None           => "whois.iana.org".to_owned()
        };
    let port =
        match port_option {
            Some(port) => port,
            None       => "4343".to_owned()
        };

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let remote = core.remote();

    info!("Loading data");
    let _unused =
        context.ipv4.get_longest_match(
            Ipv4Net::from_str("0.0.0.0/32").unwrap()
        );
    info!("Finished loading data");

    let addr = format!("0.0.0.0:{}", port).parse().unwrap();
    let tcp_listener = TcpListener::bind(&addr, &handle).unwrap();
    info!("Listening on port {}", port);

    let server = tcp_listener.incoming().for_each(move |(client, client_addr)| {
        let start_time = time::get_time();
        let (client_reader, client_writer) = client.split();
        let buf_reader = BufReader::new(client_reader);
        let remote_ = remote.clone();
        let default_server_ = default_server.to_owned();
        let handler = lines(buf_reader)
                .into_future()
                .map_err(|e| e.0).
                and_then(move |(line, _)| {
            let mut line_data = line.unwrap();
            let line_data_original = line_data.clone();
            let server = match context.lookup(&line_data) {
                Some(server) => {
                    info!("'{}' from {} redirecting to {}",
                          &line_data, client_addr, server);
                    server
                },
                None => {
                    info!("'{}' from {} not handled, redirecting to {}",
                          &line_data, client_addr, &default_server_);
                    &default_server_
                }
            };
            let mut server_spec = server.to_string();
            server_spec.push_str(":43");
            let target: &str = &server_spec;
            let server = tcp_connect(target, remote_);
            server.and_then(move |server| {
                let (server_reader, server_writer) = server.split();
                line_data.push_str("\r\n");

                write_all(server_writer, line_data).and_then(move |(socket, _)| {
                    copy(server_reader, client_writer)
                        .and_then(move |(n, _, client_writer)| {
                            let end_time = time::get_time();
                            let duration = end_time - start_time;
                            info!("'{}' from {} completed ({}ms)",
                                  &line_data_original, client_addr,
                                  duration.num_milliseconds());

                            shutdown(client_writer).map(move |_| n).join(
                                shutdown(socket).map(move |_| n))
                        })
                })
            })
        });
        handle.spawn(handler.map(|_| {}).map_err(|_| {}));
        Ok(())
    });

    core.run(server).unwrap();
}

/* Taken from tokio-core/examples/proxy.rs. */

#[derive(Clone)]
struct MyTcpStream(Arc<TcpStream>);

impl Read for MyTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for MyTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for MyTcpStream {}

impl AsyncWrite for MyTcpStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        try!(self.0.shutdown(Shutdown::Write));
        Ok(().into())
    }
}
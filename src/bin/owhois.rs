extern crate env_logger;
extern crate getopts;
extern crate ipnet;
extern crate owhois;

use getopts::Options;

use std::env;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("", "default-server", "default Whois server for unhandled resources", "HOSTNAME");
    opts.optopt("", "port", "server port number", "PORT");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m)  => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    let hostname = matches.opt_str("default-server");
    let port = matches.opt_str("port");

    owhois::server::run(hostname, port);
}

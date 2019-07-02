use failure::{bail, Error};
use futures::Future;
use log::debug;
use quicli::prelude::Verbosity;
use std::net::SocketAddr;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;
use trust_dns_resolver::AsyncResolver;

#[derive(Debug, StructOpt)]
enum Protocol {
    /// The QUIC protocol, from google, built to improve upon TCP. Underlying protocol of HTTP/3.
    #[structopt(name = "quic")]
    Quic(QuicOptions),
}

#[derive(Debug, StructOpt)]
struct QuicOptions {
    /// The hostname used to validate TLS connections to the remote. Will default to the provided
    /// hostname.
    #[structopt(long = "dns-name")]
    dns_name: Option<String>,
}

#[derive(Debug, StructOpt)]
struct Options {
    /// The hostname or IP address to connect to.
    hostname: String,
    /// The port number to connect to
    port: u16,
    #[structopt(flatten)]
    protocol: Protocol,
    #[structopt(flatten)]
    verbosity: Verbosity,
}

impl Options {
    /// Initialise everything
    pub fn setup(&self) -> Result<Runtime, Error> {
        self.verbosity.setup_env_logger("netcat")?;
        let runtime = Runtime::new()?;
        debug!("Runtime initialized");
        Ok(runtime)
    }

    /// Find the IP address of the remote host
    pub fn get_address<'a>(&'a self) -> impl 'a + Future<Item = SocketAddr, Error = Error> {
        let resolver = futures::future::ok(()).and_then(|_| {
            AsyncResolver::from_system_conf().map(|(resolver, driver)| {
                tokio::spawn(driver);
                debug!("Created DNS resolver {:?}", resolver);
                resolver
            })
        });

        let responses =
            resolver.and_then(move |resolver| resolver.lookup_ip(self.hostname.as_str()));

        let ip =
            responses
                .map_err(Error::from)
                .and_then(|responses| match responses.iter().next() {
                    Some(output) => Ok(output),
                    None => bail!("No DNS record found"),
                });

        let output = ip.map(move |ip| {
            let addr = (ip, self.port).into();
            debug!("Found address {}", addr);
            addr
        });

        output
    }
}

fn main() -> Result<(), Error> {
    let options = Options::from_args();
    let mut runtime = options.setup()?;

    let address = options.get_address();
    let address = runtime.block_on(address)?;

    println!("{}", address);

    Ok(())
}

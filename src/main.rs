use failure::{bail, Error};
use futures::{future::FutureResult, Future};
use log::{debug, error, info};
use quicli::prelude::Verbosity;
use quinn::Endpoint;
use std::net::SocketAddr;
use structopt::StructOpt;
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    runtime::current_thread::Runtime,
};
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

impl QuicOptions {
    /// Create a connection to the remote address. In case an explicit dns_name was not provided,
    /// the initial hostname is required for TLS verification of the domain.
    pub fn connect<'a>(
        &'a self,
        address: SocketAddr,
        hostname: &'a str,
    ) -> impl 'a + Future<Item = (impl AsyncRead, impl AsyncWrite), Error = Error> {
        let endpoint = Endpoint::builder().bind("[::]:0").map_err(Error::from).map(
            |(driver, endpoint, _incomming)| {
                tokio::spawn(driver.map_err(|err| error!("Endpoint error {}", err)));
                endpoint
            },
        );
        let endpoint = FutureResult::from(endpoint);

        let server_name = self
            .dns_name
            .as_ref()
            .map(String::as_str)
            .unwrap_or(hostname);

        let connection = endpoint
            .and_then(move |endpoint| endpoint.connect(&address, server_name).map_err(Error::from))
            .and_then(|connecting| connecting.map_err(Error::from))
            .map(|(driver, connection, _incomming)| {
                tokio::spawn(driver.map_err(|err| error!("Connection error {}", err)));

                connection
            });

        let output = connection
            .and_then(|connection| connection.open_bi().map_err(Error::from))
            .map(|(send, recv)| (recv, send));

        output.inspect(|_| info!("Connection established"))
    }
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
            info!("Found address {}", addr);
            addr
        });

        output
    }
}

/// Once a streaming connection has been established with the remote, run it to completion.
/// Connects the read end of the stream to stdout, and the write end of the stream to stdin.
fn run_stream_connection(
    recv: impl AsyncRead,
    send: impl AsyncWrite,
) -> impl Future<Item = (), Error = Error> {
    let read = io::stdin();
    let write = io::stdout();

    let main = Future::join(io::copy(read, send), io::copy(recv, write)).map_err(Error::from);

    main.map(|((sent, _, _), (received, _, _))| {
        info!(
            "Connection closed. Sent {} bytes, received {} bytes.",
            sent, received
        )
    })
}

fn main() -> Result<(), Error> {
    let options = Options::from_args();
    let mut runtime = options.setup()?;

    let address = options.get_address();

    let conn = address.and_then(|addr| {
        let Options {
            protocol, hostname, ..
        } = &options;
        let Protocol::Quic(quic_options) = protocol;
        quic_options.connect(addr, hostname)
    });

    let main = conn.and_then(|(recv, send)| run_stream_connection(recv, send));

    runtime.block_on(main)
}

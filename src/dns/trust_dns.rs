//! DNS resolution via the [trust_dns_resolver](https://github.com/bluejekyll/trust-dns) crate

use hyper::client::connect::dns::Name;
use once_cell::sync::OnceCell;
pub use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::{lookup_ip::LookupIpIntoIter, system_conf, TokioAsyncResolver};

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use super::{Addrs, Resolve, Resolving};

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Default, Clone)]
pub(crate) struct TrustDnsResolver {
    /// Since we might not have been called in the context of a
    /// Tokio Runtime in initialization, so we must delay the actual
    /// construction of the resolver.
    state: Arc<OnceCell<TokioAsyncResolver>>,
}

struct SocketAddrs {
    iter: LookupIpIntoIter,
}

impl Resolve for TrustDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let resolver = resolver.state.get_or_try_init(new_resolver)?;

            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });
            Ok(addrs)
        })
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

/// Create a new resolver with the default configuration,
/// which reads from `/etc/resolve.conf`.
fn new_resolver() -> io::Result<TokioAsyncResolver> {
    let alidns_ips = vec![
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(223, 5, 5, 5)),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(223, 6, 6, 6)),
    ];
    let name_server = trust_dns_resolver::config::NameServerConfigGroup::from_ips_https(
        &alidns_ips,
        443,
        "dns.alidns.com".to_string(),
        true,
    );
    let config = ResolverConfig::from_parts(None, vec![], name_server);
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = false;
    Ok(TokioAsyncResolver::tokio(config, opts))
}

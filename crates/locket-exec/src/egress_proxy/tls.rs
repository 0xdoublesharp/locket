use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use data_encoding::BASE64;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use tempfile::NamedTempFile;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::destination::{Authority, Resolver};
use super::http::{self, Request};
use super::wire::{self, SocketWriter, Wire};
use super::{EgressBlockReason, REQUEST_TIMEOUT, RESPONSE_TIMEOUT, Rejection, State};

const CA_LIFETIME: Duration = Duration::hours(24);
const LEAF_LIFETIME: Duration = Duration::hours(1);
const CLOCK_SKEW: Duration = Duration::minutes(5);
const HTTP_1_1: &[u8] = b"http/1.1";

struct CertificateAuthority {
    cert: Certificate,
    key: Zeroizing<KeyPair>,
    expires: OffsetDateTime,
}

impl CertificateAuthority {
    fn new() -> Result<Self, rcgen::Error> {
        let now = OffsetDateTime::now_utc();
        let expires = now + CA_LIFETIME;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "Locket per-run egress CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.not_before = now - CLOCK_SKEW;
        params.not_after = expires;
        let key = Zeroizing::new(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?);
        let cert = params.self_signed(&key)?;
        Ok(Self { cert, key, expires })
    }

    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
        let now = OffsetDateTime::now_utc();
        if now >= self.expires {
            return Err(io::Error::other("egress CA expired").into());
        }
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = now - CLOCK_SKEW;
        params.not_after = (now + LEAF_LIFETIME).min(self.expires);
        let key = Zeroizing::new(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?);
        let leaf = params.signed_by(&*key, &self.cert, &self.key)?;
        // Load the provider key from a borrowed slice so no new PKCS#8 buffer is needed.
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialized_der()));
        let signing_key = aws_lc_rs::sign::any_ecdsa_type(&der)?;
        let certified = CertifiedKey::new(vec![leaf.der().clone()], signing_key);
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        config.alpn_protocols = vec![HTTP_1_1.to_vec()];
        Ok(Arc::new(config))
    }
}

pub(super) struct Tls {
    authority: CertificateAuthority,
    bundle: NamedTempFile,
    upstream: Arc<ClientConfig>,
}

impl Tls {
    pub(super) fn new(extra_roots: Option<&[u8]>) -> Result<Self, Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let mut bundle = NamedTempFile::new()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            bundle.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut roots = RootCertStore::empty();
        // Some native stores contain unusable entries. Include only certificates
        // rustls can use, as opposed to silently accepting malformed configured roots.
        for cert in rustls_native_certs::load_native_certs().certs {
            if roots.add(cert.clone()).is_ok() {
                write_pem(&mut bundle, &cert)?;
            }
        }
        if let Some(pem) = extra_roots {
            let certs = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>()?;
            if certs.is_empty() {
                return Err(io::Error::other("no configured upstream CA certificates").into());
            }
            for cert in certs {
                roots.add(cert.clone())?;
                write_pem(&mut bundle, &cert)?;
            }
        }
        if roots.is_empty() {
            return Err(io::Error::other("no usable upstream CA certificates").into());
        }
        // The broker's root is trusted by the child only.
        write_pem(&mut bundle, authority.cert.der())?;
        bundle.flush()?;
        Ok(Self { authority, bundle, upstream: client_config(roots)? })
    }

    pub(super) fn bundle_path(&self) -> &Path {
        self.bundle.path()
    }

    pub(super) fn serve(
        &self,
        state: &State,
        destination: &Authority,
        transport: &mut Wire<'_, &TcpStream>,
        output: &mut SocketWriter<'_>,
    ) -> Result<(), Rejection> {
        let unavailable = EgressBlockReason::UpstreamUnavailable;
        let pinned = state.pin(destination)?;
        let config = self.authority.server_config(&destination.host).map_err(|_| unavailable)?;
        let conn = ServerConnection::new(config).map_err(|_| unavailable)?;
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        output.deadline = deadline;
        if output.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
            return Ok(());
        }
        // Any bytes read past the CONNECT headers belong to the TLS transport.
        transport.set_deadline(deadline);
        let mut session = StreamOwned::new(conn, transport);
        let invalid = EgressBlockReason::InvalidRequest;
        if session.conn.complete_io(&mut *session.sock).is_err()
            || session.conn.is_handshaking()
            || session.conn.server_name().is_some_and(|sni| {
                Authority::parse(sni, Some(destination.port)).as_ref() != Some(destination)
            })
        {
            state.audit(Some(destination), None, Some(invalid));
            return Ok(());
        }

        let mut client = Wire::new(session, &state.stopping, deadline);
        if let Err(rejected) = self.exchange(state, destination, &pinned, &mut client) {
            let deadline = Instant::now() + super::SOCKET_POLL;
            client.set_deadline(deadline);
            client.stream_mut().sock.set_deadline(deadline);
            state.reject(&mut client, Some(destination), rejected);
        }
        client.stream_mut().conn.send_close_notify();
        let _ignored = client.flush();
        Ok(())
    }

    fn exchange(
        &self,
        state: &State,
        destination: &Authority,
        pinned: &[SocketAddr],
        client: &mut Wire<'_, StreamOwned<ServerConnection, &mut Wire<'_, &TcpStream>>>,
    ) -> Result<(), Rejection> {
        let head = client.head().map_err(|_| EgressBlockReason::InvalidRequest)?;
        let prepared = parse_request(state, destination, client, &head)?;

        let unavailable = EgressBlockReason::UpstreamUnavailable;
        let socket = Resolver::connect_pinned(pinned, &state.stopping)?;
        let name = ServerName::try_from(destination.host.to_string()).map_err(|_| unavailable)?;
        let conn =
            ClientConnection::new(Arc::clone(&self.upstream), name).map_err(|_| unavailable)?;
        let transport = Wire::new(&socket, &state.stopping, Instant::now() + REQUEST_TIMEOUT);
        let mut upstream = StreamOwned::new(conn, transport);
        // Finish certificate and hostname verification before queuing any plaintext.
        upstream.conn.complete_io(&mut upstream.sock).map_err(|_| unavailable)?;
        if upstream.conn.is_handshaking() {
            return Err(unavailable.into());
        }

        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        upstream.sock.set_deadline(deadline);
        let mut upstream = Wire::new(upstream, &state.stopping, deadline);
        client.stream_mut().sock.set_deadline(deadline);
        client.set_deadline(deadline);
        http::forward(state, prepared, destination, true, &mut upstream, client)
    }
}

fn parse_request<'a>(
    state: &State,
    destination: &Authority,
    client: &mut Wire<'_, impl Read>,
    head: &'a [u8],
) -> Result<http::PreparedRequest<'a>, Rejection> {
    let invalid = EgressBlockReason::InvalidRequest;
    let (line, headers) = wire::parse_head(head).ok_or(invalid)?;
    let request = Request::parse_line(line, true).ok_or(invalid)?;
    if !http::host_matches(&headers, destination, 443)
        || wire::named(&headers, "Proxy-Authorization").next().is_some()
    {
        return Err(invalid.into());
    }
    if let Some(raw) = request.authority {
        if Authority::parse(raw, Some(443)).as_ref() != Some(destination) {
            return Err(invalid.into());
        }
        state.guard_authority(raw, destination)?;
    }
    let framing = request.framing(&headers).ok_or(invalid)?;
    http::prepare(state, &request, &headers, client, framing, destination)
}

fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, rustls::Error> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![HTTP_1_1.to_vec()];
    Ok(Arc::new(config))
}

fn write_pem(writer: &mut impl Write, cert: &CertificateDer<'_>) -> io::Result<()> {
    writer.write_all(b"-----BEGIN CERTIFICATE-----\n")?;
    for line in BASE64.encode(cert.as_ref()).as_bytes().chunks(64) {
        writer.write_all(line)?;
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"-----END CERTIFICATE-----\n")
}

#[cfg(test)]
mod tests;

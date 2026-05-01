use crate::Result;
use crate::cachestr::Cachestr;
use deadpool::managed;
use deadpool::managed::{Metrics, RecycleError, RecycleResult};
use futures::{FutureExt, future};
use hashbrown::HashMap;
use hyper_rustls::ConfigBuilderExt;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error, SignatureScheme};
use std::future::Future;
use std::net::SocketAddr;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

#[derive(Debug)]
struct NoVerifyServerCertVerifier;

impl ServerCertVerifier for NoVerifyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> StdResult<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> StdResult<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> StdResult<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            // SignatureScheme::RSA_PKCS1_SHA256,
            // SignatureScheme::ECDSA_NISTP256_SHA256,
            // SignatureScheme::ED25519,
        ]
    }
}

static DEFAULT_TLS_CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let c = rustls::ClientConfig::builder()
        .with_native_roots()
        .unwrap()
        .with_no_client_auth();
    Arc::new(c)
});

static DEFAULT_HTTPS_CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut c = rustls::ClientConfig::builder()
        .with_native_roots()
        .unwrap()
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
});

static INSECURE_TLS_CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let c = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyServerCertVerifier))
        .with_no_client_auth();
    Arc::new(c)
});

static INSECURE_HTTPS_CLIENT_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut c = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyServerCertVerifier))
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
});

pub(crate) type Pool = managed::Pool<Manager>;

pub(crate) const FLAG_INSECURE: u8 = 0x01;
pub(crate) const FLAG_ALPN: u8 = 0x01 << 1;

pub(crate) type Key = (
    Cachestr,   // domain
    SocketAddr, // socket addr
    u8,         // flags
);

pub(crate) struct Manager {
    key: Key,
    lifetime: Duration,
}

impl Manager {
    #[inline]
    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        pub(crate) const FLAG_INSECURE: u8 = 0x01;
        pub(crate) const FLAG_ALPN: u8 = 0x01 << 1;

        const FLAG_BOTH: u8 = FLAG_INSECURE | FLAG_ALPN;
        let client_config = Clone::clone(match self.key.2 {
            FLAG_INSECURE => &*INSECURE_TLS_CLIENT_CONFIG,
            FLAG_ALPN => &*DEFAULT_HTTPS_CLIENT_CONFIG,
            FLAG_BOTH => &*INSECURE_TLS_CLIENT_CONFIG,
            _ => &*DEFAULT_TLS_CLIENT_CONFIG,
        });

        let connector = TlsConnector::from(client_config);
        let server_name = ServerName::try_from(self.key.0.to_string())?;
        let stream = TcpStream::connect(self.key.1).await?;
        let stream = connector.connect(server_name, stream).await?;
        Ok(stream)
    }
}

#[async_trait::async_trait]
impl managed::Manager for Manager {
    type Type = (u32, TlsStream<TcpStream>);
    type Error = anyhow::Error;

    fn create(&self) -> impl Future<Output = std::result::Result<Self::Type, Self::Error>> + Send {
        self.connect().map(|it| it.map(|it| (0, it)))
    }

    fn recycle(
        &self,
        obj: &mut Self::Type,
        metrics: &Metrics,
    ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
        if metrics.created.elapsed() > self.lifetime {
            return future::err(RecycleError::Backend(anyhow!("exceed max lifetime!")));
        }

        if obj.0 != 0 {
            return future::err(RecycleError::Backend(anyhow!("invalid connection!")));
        }

        if let Err(e) = validate(&obj.1) {
            return future::err(RecycleError::Backend(e));
        }

        future::ok(())
    }
}

#[inline]
fn validate(stream: &TlsStream<TcpStream>) -> Result<()> {
    let (c, _) = stream.get_ref();
    super::tcp::validate(c)
}

pub(crate) fn get(sni: &str, addr: SocketAddr, flags: u8) -> Result<Pool> {
    static POOLS: Lazy<Arc<RwLock<HashMap<Key, Pool>>>> = Lazy::new(Default::default);

    let key = (Cachestr::from(sni), addr, flags);

    let pools = POOLS.clone();

    {
        let r = pools.read();
        if let Some(existing) = r.get(&key) {
            return Ok(Clone::clone(existing));
        }
    }

    let mut w = pools.write();
    if let Some(existing) = w.get(&key) {
        return Ok(Clone::clone(existing));
    }

    let mgr = Manager {
        key: Clone::clone(&key),
        lifetime: Duration::from_secs(60),
    };
    let pool = Pool::builder(mgr).max_size(8).build()?;
    w.insert(key, Clone::clone(&pool));

    Ok(pool)
}

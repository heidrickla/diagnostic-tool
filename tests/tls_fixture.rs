//! Offline TLS boundary tests. No socket, account, relay, or lasting credential.
//! This verifies server certificate/name validation and encrypted records only.
//! It does not authenticate an operator or implement production transport.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

const FIXTURE_HOST: &str = "relay.fixture.invalid";

fn fixture_connections(
    trusted_cert: bool,
    requested_host: &str,
) -> (ClientConnection, ServerConnection) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![FIXTURE_HOST.to_owned()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    if trusted_cert {
        roots.add(cert.der().clone()).unwrap();
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(requested_host.to_owned()).unwrap(),
    )
    .unwrap();
    let server = ServerConnection::new(Arc::new(server_config)).unwrap();
    (client, server)
}

fn move_records(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    let mut to_server = Vec::new();
    client.write_tls(&mut to_server).unwrap();
    if !to_server.is_empty() {
        server.read_tls(&mut Cursor::new(to_server)).unwrap();
        server.process_new_packets()?;
    }

    let mut to_client = Vec::new();
    server.write_tls(&mut to_client).unwrap();
    if !to_client.is_empty() {
        client.read_tls(&mut Cursor::new(to_client)).unwrap();
        client.process_new_packets()?;
    }
    Ok(())
}

fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    for _ in 0..12 {
        move_records(client, server)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("fixture handshake did not settle")
}

#[test]
fn authenticated_tls_records_round_trip_without_network() {
    let (mut client, mut server) = fixture_connections(true, FIXTURE_HOST);
    handshake(&mut client, &mut server).unwrap();
    client.writer().write_all(b"catalog:os.version").unwrap();
    move_records(&mut client, &mut server).unwrap();
    let mut received = [0u8; 18];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"catalog:os.version");
}

#[test]
fn wrong_hostname_fails_certificate_verification() {
    let (mut client, mut server) = fixture_connections(true, "other.fixture.invalid");
    assert!(handshake(&mut client, &mut server).is_err());
}

#[test]
fn untrusted_certificate_fails_verification() {
    let (mut client, mut server) = fixture_connections(false, FIXTURE_HOST);
    assert!(handshake(&mut client, &mut server).is_err());
}

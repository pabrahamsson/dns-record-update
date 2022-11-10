#![allow(clippy::redundant_field_names)]
extern crate env_logger;
extern crate google_dns1 as dns1;

use dns1::{api::ResourceRecordSet, Dns, Error as CDError, hyper, hyper_rustls, oauth2};
use http::StatusCode;
use log::{debug, info, warn};
use opentelemetry::{
    global,
    sdk::trace as sdktrace,
    trace::{FutureExt, Span, TraceContextExt, TraceError, Tracer},
    Context, KeyValue,
};
use rsdns::{
    clients::{tokio::Client, ClientConfig},
    constants::Class,
    records::data::A,
};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    thread,
    time::Duration,
};
use vaultrs::{
    auth::kubernetes::login,
    client::{Client as VCClient, VaultClient, VaultClientSettingsBuilder},
    error::ClientError,
};

const JWT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const LOOKUP_HOSTNAME: &str = "myip.opendns.com";
const RESOLVER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222));
const DNS_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
const VAULT_ADDR: &str = "http://vault.vault.svc:8200";

pub struct Config<'a> {
    project: &'a str,
    zone: &'a str,
    record: &'a str,
}

impl<'a> Config<'a> {
    pub fn new(args: &[String]) -> Result<Config, &str> {
        if args.len() != 4 {
            return Err("Incorrect number of arguments");
        }

        let project =&args[1];
        let zone = &args[2];
        let record = &args[3];

        Ok(Config { project, zone, record })
    }
}

#[derive(Serialize)]
pub struct LogMessage {
    pub timestamp: String,
    pub loglevel: String,
    pub message: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultToken {
    ttl: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Token {
    data: VaultToken,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultAuth {
    client_token: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Lease {
    auth: VaultAuth,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultKV2Data {
    data: serde_json::Value,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct CloudDnsServiceAccount {
    serviceaccount: String,
}

/*
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
*/

async fn get_record_set(
    project: &str,
    zone_identifier: &str,
    record_name: &str,
    api_client: &Dns<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
) -> Result<ResourceRecordSet, CDError> {
    let tracer = global::tracer("get_record_set");
    let mut span = tracer.start("Looking up record_set...");
    span.set_attribute(KeyValue::new("dns.record", record_name.to_string()));
    span.set_attribute(KeyValue::new("dns.zone", zone_identifier.to_string()));
    let cx = Context::current_with_span(span);

    match api_client
        .resource_record_sets()
        .get(project, zone_identifier, record_name, "A")
        .doit()
        .with_context(cx)
        .await {
            Ok((res, rrset)) => {
                if res.status() == StatusCode::OK {
                    Ok(rrset)
                } else {
                    Ok(ResourceRecordSet::default())
                }
            },
            Err(e) => {
                warn!("{:?}", e);
                Err(e)
            },
    }
}

async fn update_record(
    rrset: ResourceRecordSet,
    project: &str,
    zone_identifier: &str,
    record_name: &str,
    api_client: &Dns<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>
) -> Option<()> {
    let tracer = global::tracer("gupdate_record");
    let mut span = tracer.start("GUpdating record...");
    span.set_attribute(KeyValue::new("dns.address", rrset.rrdatas.as_ref().unwrap()[0].clone()));
    span.set_attribute(KeyValue::new("dns.name", record_name.to_string()));
    let cx = Context::current_with_span(span);

    match api_client
        .resource_record_sets()
        .patch(rrset, project, zone_identifier, record_name, "A")
        .doit()
        .with_context(cx.clone())
        .await {
            Ok((_,_)) => Some(()),
            Err(e) => {
                warn!("{:?}", e);
                None
            },
        }
}

async fn create_clouddns_client(client: &VaultClient) -> Dns<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>> {
    let tracer = global::tracer("create_clouddns_client");
    let span = tracer.start("Create Cloud DNS API Client...");
    let cx = Context::current_with_span(span);

    let vault_response: CloudDnsServiceAccount = vaultrs::kv2::read(client, "ocp/cf-dyn-dns", "clouddns-api")
        .with_context(cx.clone())
        .await
        .unwrap();
    let serviceaccountkey: oauth2::ServiceAccountKey = serde_json::from_str(&vault_response.serviceaccount).unwrap();
    let authenticator = oauth2::ServiceAccountAuthenticator::builder(serviceaccountkey)
        .build()
        .with_context(cx.clone())
        .await
        .unwrap();
    Dns::new(
        hyper::Client::builder()
            .build(
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .https_or_http()
                    .enable_http1()
                    .enable_http2()
                    .build()),
        authenticator)
}

async fn dns(project: &str, zone_name: &str, record_name: &str) {
    let tracer = global::tracer("dns");
    let span = tracer.start("Dns logic...");
    let cx = Context::current_with_span(span);

    let (current_ip, lookup_ip) = futures_util::future::join(
        dns_lookup(RESOLVER_ADDRESS, LOOKUP_HOSTNAME),
        dns_lookup(DNS_ADDRESS, record_name),
    )
    .with_context(cx.clone())
    .await;

    if current_ip == lookup_ip {
        info!(
            "DNS record for {} ({}) is up to date",
            record_name, &lookup_ip
        )
    } else {
        info!(
            "DNS record for {} ({} ==> {}) will be updated",
            record_name, &lookup_ip, &current_ip
        );
        let api_client = create_clouddns_client(&create_vault_client().await.unwrap())
            .with_context(cx.clone())
            .await;
        let mut rrset = get_record_set(project, zone_name, record_name, &api_client)
            .with_context(cx.clone())
            .await
            .unwrap();
        rrset.rrdatas = Some(vec!(current_ip.to_string()));
        update_record(rrset, project, zone_name, record_name, &api_client)
            .with_context(cx.clone())
            .await;
    }
}

async fn dns_lookup(resolver: IpAddr, hostname: &str) -> Ipv4Addr {
    let tracer = global::tracer("dns_lookup");
    let mut span = tracer.start("Getting current dns address...");
    span.set_attribute(KeyValue::new("dns.hostname", hostname.to_string()));
    span.set_attribute(KeyValue::new("dns.resolver", resolver.to_string()));
    let cx = Context::current_with_span(span);

    let nameserver = SocketAddr::new(resolver, 53);
    let config = ClientConfig::with_nameserver(nameserver);
    let mut client = Client::new(config).await.unwrap();
    let rrset = client
        .query_rrset::<A>(hostname, Class::In)
        .with_context(cx)
        .await
        .unwrap();
    debug!("A record: {}", rrset.rdata[0].address);
    rrset.rdata[0].address
}

async fn create_vault_client() -> Result<VaultClient, ClientError> {
    let tracer = global::tracer("create_vault_client");
    let span = tracer.start("Creating vault client...");
    let cx = Context::current_with_span(span);

    let vault_addr = env::var("VAULT_ADDR").unwrap_or_else(|_| VAULT_ADDR.to_string());
    let mut vault_client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&vault_addr)
            .verify(true)
            .build()
            .unwrap(),
    )
    .unwrap();
    let jwt_token_path = env::var("JWT_TOKEN_PATH").unwrap_or_else(|_| JWT_TOKEN_PATH.to_string());
    let jwt = fs::read_to_string(jwt_token_path).unwrap();
    let mount = "ocp/cf-dyn-dns-k8s";
    let role = "cf-dyn-dns-secret-reader";
    match login(&vault_client, mount, role, &jwt)
        .with_context(cx.clone())
        .await {
            Ok(response) => {
                vault_client.set_token(&response.client_token);
                Ok(vault_client)
            }
            Err(e) => Err(e),
    }
}

fn init_tracer() -> Result<sdktrace::Tracer, TraceError> {
    opentelemetry_jaeger::new_agent_pipeline()
        .with_service_name("cf-dyn-dns")
        .install_simple()
    /*
    .with_batch_processor_config(
        sdktrace::BatchConfig::default().with_max_queue_size(10)
    )
    .install_batch(opentelemetry::runtime::Tokio)
    */
}

pub async fn run(
    config: Config<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {

    loop {
        let tracer = init_tracer()?;
        let span = tracer.start("root");
        let cx = Context::current_with_span(span);

        dns(config.project, config.zone, config.record)
            .with_context(cx)
            .await;

        global::shutdown_tracer_provider();
        thread::sleep(Duration::from_secs(120));
    }
}

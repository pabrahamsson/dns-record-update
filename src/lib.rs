#![allow(clippy::redundant_field_names)]
extern crate cloudflare;
extern crate env_logger;

use cloudflare::endpoints::dns;
use cloudflare::framework::{
    async_api::Client as CFClient, auth::Credentials, response::ApiFailure, Environment,
    HttpApiClientConfig,
};

use log::{debug, info, warn};
use opentelemetry::{
    global,
    trace::{FutureExt, Span, TraceContextExt, TraceError, Tracer},
    Context, KeyValue,
};
use opentelemetry_sdk::trace as sdktrace;
use rsdns::{
    clients::{tokio::Client, ClientConfig},
    records::{data::A, Class},
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
const CF_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
const VAULT_ADDR: &str = "http://vault.vault.svc:8200";

pub struct Config<'a> {
    zone: &'a str,
    zone_id: &'a str,
    record: &'a str,
}

impl<'a> Config<'a> {
    pub fn new(args: &[String]) -> Result<Config, &str> {
        if args.len() != 4 {
            return Err("Incorrect number of arguments");
        }

        let zone_id = &args[1];
        let zone = &args[2];
        let record = &args[3];

        Ok(Config {
            zone_id,
            zone,
            record,
        })
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
struct VaultKV2 {
    key: String,
}

/*
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
*/

async fn handle_cf_error(api_failure: &ApiFailure) {
    match api_failure {
        ApiFailure::Error(status, errors) => {
            warn!("HTTP {}:", status);
            for err in &errors.errors {
                warn!("Error {}: {}", err.code, err.message);
                for (k, v) in &err.other {
                    warn!("{}: {}", k, v);
                }
            }
            for (k, v) in &errors.other {
                warn!("{}: {}", k, v);
            }
        }
        ApiFailure::Invalid(reqwest_err) => warn!("Error: {}", reqwest_err),
    }
}

async fn get_current_record(
    record_name: &str,
    zone_identifier: &str,
    api_client: &CFClient,
) -> Option<String> {
    let tracer = global::tracer("get_current_record");
    let mut span = tracer.start("Looking up current record...");
    span.set_attribute(KeyValue::new("dns.record", record_name.to_string()));
    span.set_attribute(KeyValue::new("dns.zone", zone_identifier.to_string()));
    let cx = Context::current_with_span(span);

    match api_client
        .request(&dns::ListDnsRecords {
            zone_identifier,
            params: dns::ListDnsRecordsParams {
                name: Some(record_name.to_string()),
                ..Default::default()
            },
        })
        .with_context(cx)
        .await
    {
        Ok(records) => {
            if records.result.len() == 1 {
                Some(records.result[0].id.clone())
            } else {
                panic!("Unable to lookup address for: {}", record_name)
            }
        }
        Err(e) => {
            handle_cf_error(&e).await;
            None
        }
    }
}

async fn update_record(
    zone_identifier: &str,
    record_name: &str,
    ip_address: &Ipv4Addr,
    api_client: &CFClient,
) -> Option<()> {
    let tracer = global::tracer("update_record");
    let mut span = tracer.start("Updating record...");
    span.set_attribute(KeyValue::new("dns.address", ip_address.to_string()));
    span.set_attribute(KeyValue::new("dns.name", record_name.to_string()));
    let cx = Context::current_with_span(span);

    let record_identifier = get_current_record(record_name, zone_identifier, api_client)
        .with_context(cx.clone())
        .await
        .unwrap();

    match api_client
        .request(&dns::UpdateDnsRecord {
            zone_identifier,
            identifier: &record_identifier,
            params: dns::UpdateDnsRecordParams {
                ttl: Some(60),
                proxied: None,
                name: record_name,
                content: dns::DnsContent::A {
                    content: *ip_address,
                },
            },
        })
        .with_context(cx)
        .await
    {
        Ok(_) => Some(()),
        Err(e) => {
            handle_cf_error(&e).await;
            None
        }
    }
}

async fn create_cf_api_client(client: &VaultClient) -> CFClient {
    let tracer = global::tracer("create_cf_api_client");
    let mut span = tracer.start("Create CF API Client...");

    let response: VaultKV2 = vaultrs::kv2::read(client, "ocp/cf-dyn-dns", "cf-api")
        //.with_context(Context::current_with_span(span))
        .await
        .unwrap();
    let credentials: Credentials = Credentials::UserAuthToken {
        token: response.key.trim_matches('"').to_string(),
    };
    let api_client = CFClient::new(
        credentials,
        HttpApiClientConfig::default(),
        Environment::Production,
    )
    .unwrap();
    span.end();
    api_client
}

async fn dns(zone_id: &str, record_name: &str) {
    let tracer = global::tracer("dns");
    let span = tracer.start("Dns logic...");
    let cx = Context::current_with_span(span);

    let (current_ip, lookup_ip) = futures_util::future::join(
        dns_lookup(RESOLVER_ADDRESS, LOOKUP_HOSTNAME),
        dns_lookup(CF_ADDRESS, record_name),
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
        let api_client = create_cf_api_client(&create_vault_client().await.unwrap())
            .with_context(cx.clone())
            .await;
        update_record(zone_id, record_name, &current_ip, &api_client)
            .with_context(cx.clone())
            .await
            .unwrap();
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
        .query_rrset::<A>(hostname, Class::IN)
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
        .await
    {
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

pub fn run(config: Config<'_>) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    loop {
        let tracer = init_tracer()?;
        let span = tracer.start("root");
        let cx = Context::current_with_span(span);

        dns(config.zone_id, config.record).with_context(cx);

        global::shutdown_tracer_provider();
        thread::sleep(Duration::from_secs(120));
    }
}

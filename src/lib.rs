#![allow(clippy::redundant_field_names)]
extern crate cloudflare;
extern crate env_logger;

use cloudflare::endpoints::{dns, zone};
use cloudflare::framework::{
    async_api::Client as CFClient, auth::Credentials, response::ApiFailure, Environment,
    HttpApiClientConfig,
};
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
    token,
};

const JWT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const LOOKUP_HOSTNAME: &str = "myip.opendns.com";
const RESOLVER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222));
const CF_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
const VAULT_ADDR: &str = "http://vault.vault.svc:8200";

pub struct Config<'a> {
    zone: &'a str,
    record: &'a str,
}

impl<'a> Config<'a> {
    pub fn new(args: &[String]) -> Result<Config, &str> {
        if args.len() != 3 {
            return Err("Incorrect number of arguments");
        }

        let zone = &args[1];
        let record = &args[2];

        Ok(Config { zone, record })
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

async fn set_default_env_var(key: &str, value: &str) {
    if env::var(key).is_err() {
        env::set_var(key, value);
    }
}

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

async fn get_zone_id(zone_name: &str, api_client: &CFClient) -> Option<String> {
    let tracer = global::tracer("get_zone_id");
    let mut span = tracer.start("Looking up dns zone...");
    span.set_attribute(KeyValue::new("dns.zone", zone_name.to_string()));
    let cx = Context::current_with_span(span);

    let response = api_client
        .request_handle(&zone::ListZones {
            params: zone::ListZonesParams {
                name: Some(zone_name.to_string()),
                ..Default::default()
            },
        })
        .with_context(cx)
        .await;
    match response {
        Ok(records) => {
            if records.result.len() == 1 {
                Some(records.result[0].id.clone())
            } else {
                panic!("No zone found for: {}", zone_name)
            }
        }
        Err(e) => {
            handle_cf_error(&e).await;
            None
        }
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

    let response = api_client
        .request_handle(&dns::ListDnsRecords {
            zone_identifier,
            params: dns::ListDnsRecordsParams {
                name: Some(record_name.to_string()),
                ..Default::default()
            },
        })
        .with_context(cx)
        .await;
    match response {
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
    record_identifier: &str,
    zone_identifier: &str,
    name: &str,
    address: &Ipv4Addr,
    api_client: &CFClient,
) -> Option<()> {
    let tracer = global::tracer("update_record");
    let mut span = tracer.start("Updating record...");
    span.set_attribute(KeyValue::new("dns.address", address.to_string()));
    span.set_attribute(KeyValue::new("dns.name", name.to_string()));
    let cx = Context::current_with_span(span);

    let response = api_client
        .request_handle(&dns::UpdateDnsRecord {
            zone_identifier,
            identifier: record_identifier,
            params: dns::UpdateDnsRecordParams {
                ttl: Some(60),
                proxied: None,
                name,
                content: dns::DnsContent::A { content: *address },
            },
        })
        .with_context(cx)
        .await;
    match response {
        Ok(_) => Some(()),
        Err(e) => {
            handle_cf_error(&e).await;
            None
        }
    }
}

async fn create_cf_api_client(credentials: Credentials) -> CFClient {
    let tracer = global::tracer("create_cf_api_client");
    let mut span = tracer.start("Create CF API Client...");

    let api_client = CFClient::new(
        credentials,
        HttpApiClientConfig::default(),
        Environment::Production,
    )
    .unwrap();
    span.end();
    api_client
}

async fn dns(zone_name: &str, record_name: &str, vault_client: &mut VaultClient) {
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
        let cf_credentials = create_cf_credential(vault_client)
            .with_context(cx.clone())
            .await
            .expect("Failed to create CF credentials");
        let api_client = create_cf_api_client(cf_credentials)
            .with_context(cx.clone())
            .await;
        let zone_identifier = get_zone_id(zone_name, &api_client)
            .with_context(cx.clone())
            .await
            .unwrap();
        let record_id = get_current_record(record_name, &zone_identifier, &api_client)
            .with_context(cx.clone())
            .await
            .unwrap();
        update_record(
            &record_id,
            &zone_identifier,
            record_name,
            &current_ip,
            &api_client,
        )
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

async fn get_vault_client_with_token(
    client: &mut VaultClient,
) -> Result<&mut VaultClient, ClientError> {
    let tracer = global::tracer("vault_token_with_client");
    let span = tracer.start("Getting vault client...");
    let cx = Context::current_with_span(span);

    if client.settings.token.is_empty()
        || (get_token_ttl(client).with_context(cx.clone()).await.unwrap() < 120)
    {
        info!("Creating Vault client with token");

        set_default_env_var("JWT_TOKEN_PATH", JWT_TOKEN_PATH).await;
        let jwt_token_path = env::var("JWT_TOKEN_PATH").unwrap();
        let jwt = fs::read_to_string(jwt_token_path).unwrap();
        let mount = "ocp/cf-dyn-dns-k8s";
        let role = "cf-dyn-dns-secret-reader";
        match login(client, mount, role, &jwt).with_context(cx.clone()).await {
            Ok(response) => {
                client.set_token(&response.client_token);
                Ok(client)
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(client)
    }
}

async fn get_token_ttl(client: &VaultClient) -> Result<u64, vaultrs::error::ClientError> {
    let tracer = global::tracer("get_token_ttl");
    let span = tracer.start("Getting vault token ttl...");
    let cx = Context::current_with_span(span);

    match token::lookup_self(client).with_context(cx).await {
        Ok(self_token) => Ok(self_token.ttl),
        Err(e) => {
            warn!("renew_vault_lease: {}", e);
            Err(e)
        }
    }
}

async fn create_cf_credential(client: &VaultClient) -> Result<Credentials, ClientError> {
    let tracer = global::tracer("create_cf_credential");
    let span = tracer.start("Creating CF api credentials...");
    let cx = Context::current_with_span(span);

    let response: VaultKV2 = vaultrs::kv2::read(client, "ocp/cf-dyn-dns", "cf-api")
        .with_context(cx)
        .await
        .unwrap();
    let credentials: Credentials = Credentials::UserAuthToken {
        token: response.key.trim_matches('"').to_string(),
    };
    Ok(credentials)
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
    set_default_env_var("VAULT_ADDR", VAULT_ADDR).await;
    let vault_addr = env::var("VAULT_ADDR").unwrap();
    let mut vault_client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&vault_addr)
            .verify(true)
            .build()
            .unwrap(),
    )
    .unwrap();

    loop {
        let tracer = init_tracer()?;
        let span = tracer.start("root");
        let cx = Context::current_with_span(span);
        let vault_client_with_token = get_vault_client_with_token(&mut vault_client)
            .with_context(cx.clone())
            .await
            .expect("Failed to get Vault client");

        dns(config.zone, config.record, vault_client_with_token)
            .with_context(cx)
            .await;

        thread::sleep(Duration::from_secs(120));
        global::shutdown_tracer_provider();
    }
}

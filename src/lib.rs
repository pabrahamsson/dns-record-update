#![allow(clippy::redundant_field_names)]
extern crate cloudflare;
extern crate env_logger;
extern crate ureq;

use std::{
    env,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    thread,
    time::Duration,
};
use cloudflare::endpoints::{dns, zone};
use cloudflare::framework::{
    async_api::{Client as CFClient},
    auth::Credentials,
    response::ApiFailure,
    Environment, HttpApiClientConfig,
};
use log::{debug, info, warn};
use rsdns::{
    constants::Class,
    records::data::A,
    clients::{
        tokio::Client,
        ClientConfig,
    }
};
use serde::{Deserialize, Serialize};
use vaultrs::{
    auth::kubernetes::login,
    client::{Client as VCClient, VaultClient, VaultClientSettingsBuilder},
    error::ClientError,
    token,
};

const JWT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const LOOKUP_HOSTNAME: &str = "myip.opendns.com";
const RESOLVER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222));
const CF_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(1,0,0,1));
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
    key: String
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
    let response = api_client.request_handle(&zone::ListZones {
        params: zone::ListZonesParams {
            name: Some(zone_name.to_string()),
            ..Default::default()
        },
    }).await;
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

async fn get_current_record(record_name: &str, zone_identifier: &str, api_client: &CFClient) -> Option<String> {
    let response = api_client.request_handle(&dns::ListDnsRecords {
        zone_identifier,
        params: dns::ListDnsRecordsParams {
            name: Some(record_name.to_string()),
            ..Default::default()
        },
    }).await;
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

async fn update_record(record_identifier: &str, zone_identifier: &str, name: &str, address: &Ipv4Addr, api_client: &CFClient) -> Option<()> {
    let response = api_client.request_handle(&dns::UpdateDnsRecord {
        zone_identifier: zone_identifier,
        identifier: record_identifier,
        params: dns::UpdateDnsRecordParams {
            ttl: Some(60),
            proxied: None,
            name: name,
            content: dns::DnsContent::A { content: *address },
        },
    }).await;
    match response {
        Ok(_) => Some(()),
        Err(e) => {
            handle_cf_error(&e).await;
            None
        }
    }
}

async fn dns(zone_name: &str, record_name: &str, api_client: &CFClient) {
    let current_ip = dns_lookup(RESOLVER_ADDRESS, LOOKUP_HOSTNAME).await.unwrap();
    let lookup_ip = dns_lookup(CF_ADDRESS, record_name).await.unwrap();
    if current_ip == lookup_ip {
        info!("DNS record for {} ({}) is up to date",
            record_name,
            &lookup_ip)
    } else {
        info!("DNS record for {} ({} ==> {}) will be updated",
            record_name,
            &lookup_ip,
            &current_ip);
        let zone_identifier = get_zone_id(zone_name, api_client).await.unwrap();
        let record_id = get_current_record(record_name, &zone_identifier, api_client).await.unwrap();
        update_record(&record_id, &zone_identifier, record_name, &current_ip, api_client).await;
    }
}

async fn dns_lookup(resolver: IpAddr, hostname: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let nameserver = SocketAddr::new(resolver, 53);
    let config = ClientConfig::with_nameserver(nameserver);
    let mut client = Client::new(config).await?;
    let rrset = client.query_rrset::<A>(hostname, Class::In).await?;
    debug!("A record: {}", rrset.rdata[0].address);
    Ok(rrset.rdata[0].address)
}

async fn get_vault_client_with_token(client: &mut VaultClient) -> Result<&mut VaultClient, ClientError> {
    set_default_env_var("JWT_TOKEN_PATH", JWT_TOKEN_PATH).await;
    let jwt_token_path = env::var("JWT_TOKEN_PATH").unwrap();
    let jwt = fs::read_to_string(jwt_token_path).unwrap();
    let mount = "ocp/cf-dyn-dns-k8s";
    let role = "cf-dyn-dns-secret-reader";
    match login(client, &mount, &role, &jwt).await {
        Ok(response) => {
            client.set_token(&response.client_token);
            Ok(client)
        },
        Err(e) => Err(e),
    }
}

async fn get_token_ttl(client: &VaultClient) -> Result<u64, vaultrs::error::ClientError> {
    match token::lookup_self(client).await {
        Ok(self_token) => Ok(self_token.ttl),
        Err(e) => {
            //handle_cf_error(&e).await;
            warn!("renew_vault_lease: {}", e);
            Err(e)
        }
    }
}

async fn get_cf_api_key(client: &VaultClient) -> Result<String, ClientError> {
    let response: VaultKV2 = vaultrs::kv2::read(client, "ocp/cf-dyn-dns", "cf-api").await.unwrap();
    Ok(response.key)
}

pub async fn run(config: Config<'_>) -> Result<(), Box<dyn std::error::Error>> {
    set_default_env_var("VAULT_ADDR", VAULT_ADDR).await;
    let vault_addr = env::var("VAULT_ADDR").unwrap();
    let mut vault_client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&vault_addr)
            .verify(true)
            .build()
            .unwrap()
    ).unwrap();
    let mut vault_client_with_token = get_vault_client_with_token(&mut vault_client).await.expect("Failed to get Vault client with token");
    loop {
        match get_token_ttl(&vault_client_with_token).await {
            Ok(ttl) => {
                if ttl < 120 {
                    vault_client_with_token = get_vault_client_with_token(&mut vault_client).await.expect("Failed to get Vault client with token");
                }
            },
            Err(_) => {
                vault_client_with_token = get_vault_client_with_token(&mut vault_client).await.expect("Failed to get Vault client with token");
            },
        }
        let cf_key = get_cf_api_key(&vault_client_with_token).await.expect("Failed to get CF api key");

        let credentials: Credentials = Credentials::UserAuthToken {
            token: cf_key.trim_matches('"').to_string(),
        };

        let api_client = CFClient::new(
            credentials,
            HttpApiClientConfig::default(),
            Environment::Production,
        ).unwrap();

        dns(config.zone, config.record, &api_client).await;

        thread::sleep(Duration::from_secs(120))
    }
}

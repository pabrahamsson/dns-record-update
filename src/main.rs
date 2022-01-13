extern crate cloudflare;
extern crate env_logger;
extern crate trust_dns_resolver;
extern crate ureq;

use std::{
    env,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    process,
    thread,
    time::Duration,
};
use chrono::Local;
use cloudflare::endpoints::{dns, zone};
use cloudflare::framework::{
    apiclient::ApiClient,
    auth::Credentials,
    response::ApiFailure,
    Environment, HttpApiClient, HttpApiClientConfig,
};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter};
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

const JWT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const LOOKUP_HOSTNAME: &str = "myip.opendns.com";
const RESOLVER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222));
const VAULT_ADDR: &str = "http://vault.vault.svc:8200";

struct Config<'a> {
    zone: &'a str,
    record: &'a str,
}

impl<'a> Config<'a> {
    fn new(args: &[String]) -> Result<Config, &str> {
        if args.len() != 3 {
            return Err("Incorrect number of arguments");
        }

        let zone = &args[1];
        let record = &args[2];

        Ok(Config { zone, record })
    }
}

#[derive(Serialize)]
struct LogMessage {
    timestamp: String,
    loglevel: String,
    message: String,
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
    data: VaultKV2Data,
}

/*
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
*/

fn handle_cf_error(api_failure: &ApiFailure) {
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

fn get_zone_id<ApiClientType: ApiClient>(zone_name: &str, api_client: &ApiClientType) -> Option<String> {
    let response = api_client.request(&zone::ListZones {
        params: zone::ListZonesParams {
            name: Some(zone_name.to_string()),
            ..Default::default()
        },
    });
    match response {
        Ok(records) => {
            if records.result.len() == 1 {
                Some(records.result[0].id.clone())
            } else {
                panic!("No zone found for: {}", zone_name.to_string())
            }
        }
        Err(e) => {
            handle_cf_error(&e);
            None
        }
    }
}

fn get_current_record<ApiClientType: ApiClient>(record_name: &str, zone_identifier: &str, api_client: &ApiClientType) -> Option<String> {
    let response = api_client.request(&dns::ListDnsRecords {
        zone_identifier,
        params: dns::ListDnsRecordsParams {
            name: Some(record_name.to_string()),
            ..Default::default()
        },
    });
    match response {
        Ok(records) => {
            if records.result.len() == 1 {
                Some(records.result[0].id.clone())
            } else {
                panic!("Unable to lookup address for: {}", record_name)
            }
        }
        Err(e) => {
            handle_cf_error(&e);
            None
        }
    }
}

fn update_record<ApiClientType: ApiClient>(record_identifier: &str, zone_identifier: &str, name: &str, address: &Option<Ipv4Addr>, api_client: &ApiClientType) -> Option<()> {
    let response = api_client.request(&dns::UpdateDnsRecord {
        zone_identifier: zone_identifier,
        identifier: record_identifier,
        params: dns::UpdateDnsRecordParams {
            ttl: Some(60),
            proxied: None,
            name: name,
            content: dns::DnsContent::A { content: address.unwrap() },
        },
    });
    match response {
        Ok(_) => Some(()),
        Err(e) => {
            handle_cf_error(&e);
            None
        }
    }
}

fn dns<ApiClientType: ApiClient>(zone_name: &str, record_name: &str, api_client: &ApiClientType) {
    let current_ip = dns_lookup(&vec![RESOLVER_ADDRESS], LOOKUP_HOSTNAME);
    let lookup_ip = dns_lookup(CLOUDFLARE_IPS, record_name);
    if &current_ip == &lookup_ip {
        info!("DNS record for {} ({}) is up to date",
            record_name,
            &lookup_ip.unwrap())
    } else {
        info!("DNS record for {} ({} ==> {}) will be updated",
            record_name,
            &lookup_ip.unwrap(),
            &current_ip.unwrap());
        let zone_identifier = get_zone_id(zone_name, api_client).unwrap();
        let record_id = get_current_record(record_name, &zone_identifier, api_client).unwrap();
        update_record(&record_id, &zone_identifier, record_name, &current_ip, api_client);
    }
}

fn dns_lookup(resolvers: &[IpAddr], hostname: &str) -> Option<Ipv4Addr> {
    let name_server_config_group = NameServerConfigGroup::from_ips_clear(resolvers, 53, true);
    let resolver_config = ResolverConfig::from_parts(None, [].to_vec(), name_server_config_group);
    let resolver = Resolver::new(resolver_config, ResolverOpts::default()).ok()?;
    let response = resolver.ipv4_lookup(hostname).ok()?;
    let address = response.iter().next().expect("no address found");
    Some(*address)
}

fn get_vault_token() -> Result<String, ureq::Error> {
    let jwt_token_path = env::var("JWT_TOKEN_PATH").ok();
    let jwt_token_path = jwt_token_path
        .as_ref()
        .map(String::as_str)
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
        .unwrap_or(JWT_TOKEN_PATH);
    let vault_addr = env::var("VAULT_ADDR").ok();
    let vault_addr = vault_addr
        .as_ref()
        .map(String::as_str)
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
        .unwrap_or(VAULT_ADDR);
    let jwt = fs::read_to_string(jwt_token_path)?;
    let mount = "kubernetes";
    let role = "cf-dyn-dns";
    let vault_login_endpoint = format!("{0}/v1/auth/{1}/login", vault_addr, mount);
    let response: Lease = ureq::post(&vault_login_endpoint)
        .set("X-Vault-Request", "true")
        .send_json(ureq::json!({
            "role": role,
            "jwt": jwt
        }))?
        .into_json()?;

    Ok(response.auth.client_token)
}

fn get_cf_api_key(token: &str) -> Result<String, ureq::Error> {
    let vault_addr = env::var("VAULT_ADDR").ok();
    let vault_addr = vault_addr
        .as_ref()
        .map(String::as_str)
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
        .unwrap_or(VAULT_ADDR);
    let vault_secret_endpoint = format!("{0}/v1/kv/data/cf-dns-gtvc-net-api", vault_addr);
    let response: VaultKV2 = ureq::get(&vault_secret_endpoint)
        .set("X-Vault-Token", token)
        .call()?
        .into_json()?;
    Ok(response.data.data["token"].to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = Config::new(&args).unwrap_or_else(|err| {
        error!("Failed to parse arguments: {}", err);
        process::exit(1)
    });
    Builder::new()
        .format(|buf, record| {
            let log_message = LogMessage {
                timestamp: format!("{}", Local::now().format("%Y-%m-%dT%H:%M:%S")),
                loglevel: record.level().to_string(),
                message: record.args().to_string(),
            };
            writeln!(buf,
                "{}",
                serde_json::to_string(&log_message).unwrap()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();

    if let Err(e) = run(config) {
        println!("Application error: {}", e);
        process::exit(1);
    }
}

fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let vault_token = get_vault_token().expect("Failed to get Vault token");
        let cf_key = get_cf_api_key(&vault_token).expect("Failed to get CF api key");

        let credentials: Credentials = Credentials::UserAuthToken {
            token: cf_key.trim_matches('"').to_string(),
        };

        let api_client = HttpApiClient::new(
            credentials,
            HttpApiClientConfig::default(),
            Environment::Production,
        ).unwrap();

        dns(&config.zone, &config.record, &api_client);

        thread::sleep(Duration::from_secs(120))
    }
}

#[macro_use]
extern crate maplit;
extern crate clap;
extern crate cloudflare;
extern crate env_logger;
extern crate trust_dns_resolver;
extern crate ureq;

use std::{
    env,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    thread,
    time::Duration,
};
use chrono::Local;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
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

type SectionFunction<ApiClientType> = fn(&ArgMatches, &ApiClientType);

struct Section<'a, ApiClientType: ApiClient> {
    args: Vec<Arg<'a, 'a>>,
    description: &'a str,
    function: SectionFunction<ApiClientType>,
}

#[derive(Serialize)]
struct LogMessage {
    timestamp: String,
    loglevel: String,
    message: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultAuthMetadata {
    role: String,
    service_account_name: String,
    service_account_namespace: String,
    service_account_secret_name: String,
    service_account_uid: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultAuth {
    client_token: String,
    accessor: String,
    policies: Vec<String>,
    token_policies: Vec<String>,
    metadata: VaultAuthMetadata,
    lease_duration: u32,
    renewable: bool,
    entity_id: String,
    token_type: String,
    orphan: bool,
}
#[derive(Deserialize)]
#[allow(dead_code)]
struct Lease {
    request_id: String,
    lease_id: String,
    renewable: bool,
    lease_duration: u32,
    data: Option<String>,
    wrap_info: Option<String>,
    warnings: Option<Vec<String>>,
    auth: VaultAuth,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultKV2Metadata {
    created_time: String,
    deletion_time: String,
    destroyed: bool,
    version: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultKV2Data {
    data: serde_json::Value,
    metadata: VaultKV2Metadata,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VaultKV2 {
    request_id: String,
    lease_id: String,
    renewable: bool,
    lease_duration: u32,
    data: VaultKV2Data,
    wrap_info: Option<String>,
    warnings: Option<Vec<String>>,
}

/*
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
*/

fn handle_cf_error(api_failure: &ApiFailure) {
    match api_failure {
        ApiFailure::Error(status, errors) => {
            //println!("HTTP {}:", status);
            warn!("HTTP {}:", status);
            for err in &errors.errors {
                //println!("Error {}: {}", err.code, err.message);
                warn!("Error {}: {}", err.code, err.message);
                for (k, v) in &err.other {
                    //println!("{}: {}", k, v);
                    warn!("{}: {}", k, v);
                }
            }
            for (k, v) in &errors.other {
                //println!("{}: {}", k, v);
                warn!("{}: {}", k, v);
            }
        }
        //ApiFailure::Invalid(reqwest_err) => println!("Error: {}", reqwest_err),
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

fn dns_lookup(resolvers: &[IpAddr], hostname: &str) -> Option<Ipv4Addr> {
    let name_server_config_group = NameServerConfigGroup::from_ips_clear(resolvers, 53, true);
    let resolver_config = ResolverConfig::from_parts(None, [].to_vec(), name_server_config_group);
    let resolver = Resolver::new(resolver_config, ResolverOpts::default()).ok()?;
    let response = resolver.ipv4_lookup(hostname).ok()?;
    let address = response.iter().next().expect("no address found");
    Some(*address)
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

fn dns<ApiClientType: ApiClient>(arg_matches: &ArgMatches, api_client: &ApiClientType) {
    let usage = "usage: dns ZONE_ID RECORD_NAME";

    let record_name_missing = format!("missing '{}': {}", "RECORD_NAME", usage);
    let record_name = arg_matches.value_of("record_name").expect(&record_name_missing);
    let zone_name_missing = format!("missing '{}': {}", "ZONE_NAME", usage);
    let zone_name = arg_matches.value_of("zone_name").expect(&zone_name_missing);

    let current_ip = dns_lookup(&vec![RESOLVER_ADDRESS], LOOKUP_HOSTNAME);
    let lookup_ip = dns_lookup(CLOUDFLARE_IPS, &record_name);
    if &current_ip == &lookup_ip {
        //println!("DNS record for {} ({}) is up to date",
        info!("DNS record for {} ({}) is up to date",
            &record_name,
            &lookup_ip.unwrap())
    } else {
        //println!("DNS record for {} ({} ==> {}) will be updated",
        info!("DNS record for {} ({} ==> {}) will be updated",
            &record_name,
            &lookup_ip.unwrap(),
            &current_ip.unwrap());
        let zone_identifier = get_zone_id(&zone_name, api_client).unwrap();
        let record_id = get_current_record(&record_name, &zone_identifier, api_client).unwrap();
        update_record(&record_id, &zone_identifier, &record_name, &current_ip, api_client);
    }
}

fn get_vault_token() -> Result<String, ureq::Error> {
    //let default_jwt_token_path: Result<String, String> = Ok(String::from(JWT_TOKEN_PATH));
    //let default_vault_addr: Result<String, String> = Ok(String::from(VAULT_ADDR));
    //let jwt_token_path = env::var("JWT_TOKEN_PATH").or(default_jwt_token_path).unwrap();
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
    let default_vault_addr: Result<String, String> = Ok(String::from("http://vault.vault.svc:8200"));
    let vault_addr = env::var("VAULT_ADDR").or(default_vault_addr).unwrap();
    let vault_secret_endpoint = format!("{0}/v1/kv/data/cf-dns-gtvc-net-api", vault_addr);
    let response: VaultKV2 = ureq::get(&vault_secret_endpoint)
        .set("X-Vault-Token", token)
        .call()?
        .into_json()?;
    Ok(response.data.data["token"].to_string())
}

//fn main() -> Result<(), Box<dyn std::error::Error>> {
fn main(){
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
                /*
                serde_json::json!({
                    "timestamp": format!("{}", Local::now().format("%Y-%m-%dT%H:%M:%S")),
                    "loglevel": record.level().as_str(),
                    "message": record.args()
                }).to_string()
                */
            )
            /*
            writeln!(buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
            */
        })
        .filter(None, LevelFilter::Info)
        .init();
    loop {
        let sections = hashmap! {
            "dns" => Section{
                args: vec![
                    Arg::with_name("zone_name").required(true),
                    Arg::with_name("record_name").required(true),
                ],
                description: "DNS records for a zone",
                function: dns
            }
        };

        let vault_token = get_vault_token();
        let cf_key = get_cf_api_key(&vault_token.unwrap());

        let mut cli = App::new("cf-rust")
            .version("0.1")
            .author("Petter Abrahamsson <petter@jebus.nu>")
            .about("Tiny Cloudflare API client")
            .arg(Arg::with_name("email")
                .long("email")
                .help("Email address associated with your account")
                .takes_value(true)
                .requires("auth-key"))
            .arg(Arg::with_name("auth-key")
                .long("auth-key")
                .env("CF_RS_AUTH_KEY")
                .help("API key generated on the \"My Account\" page")
                .takes_value(true)
                .requires("email"))
            .arg(Arg::with_name("auth-token")
                .long("auth-token")
                .env("CF_RS_AUTH_TOKEN")
                .help("API token generated on the \"My Account\" page")
                .takes_value(true)
                .conflicts_with_all(&["email", "auth-key"]))
            .setting(AppSettings::ArgRequiredElseHelp);

        for (section_name, section) in sections.iter() {
            let mut subcommand = SubCommand::with_name(section_name).about(section.description);

            for arg in &section.args {
                subcommand = subcommand.arg(arg);
            }
            cli = cli.subcommand(subcommand);
        }

        let matches = cli.get_matches();
        let matched_sections =
            sections
                .iter()
                .filter(|&(section_name, _): &(&&str, &Section<HttpApiClient>)| {
                    matches.subcommand_matches(section_name).is_some()
                });

        let email = matches.value_of("email");
        let key = matches.value_of("auth-key");
        //let token = matches.value_of("auth-token");
        let token = Some(cf_key.as_ref().unwrap().trim_matches('"'));

        let credentials: Credentials = if let Some(key) = key {
            Credentials::UserAuthKey {
                email: email.unwrap().to_string(),
                key: key.to_string(),
            }
        } else if let Some(token) = token {
            Credentials::UserAuthToken {
                token: token.to_string(),
            }
        } else {
            panic!("Either API token or API key + email pair must be provided")
        };

        let api_client = HttpApiClient::new(
            credentials,
            HttpApiClientConfig::default(),
            Environment::Production,
        //)?;
        ).unwrap();

        for (section_name, section) in matched_sections {
            (section.function)(
                matches.subcommand_matches(section_name).unwrap(),
                &api_client,
            );
        }

        //zone(matches.subcommand_matches("zone").unwrap(), &api_client);
        //list_zone(matches.subcommand_matches("zone").unwrap(), &api_client);

        //Ok(())
        thread::sleep(Duration::from_secs(120))
    }
}

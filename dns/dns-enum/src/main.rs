use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use clap::{Arg, Command};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use colored::*;

#[derive(Clone)]
struct EnumConfig {
    wordlist: String,
    target: String,
    dns_server: Option<String>,
    threads: usize,
    timeout: u64,
}

#[derive(Debug, Clone)]
struct SubdomainResult {
    subdomain: String,
    ips: Vec<IpAddr>,
}

fn main() {
    let matches = Command::new("DNS Subdomain Enumerator")
        .version("1.0")
        .author("Security Tool")
        .about("Enumerates subdomains for a target domain")
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .value_name("FILE")
                .help("Path to wordlist file")
                .required(true),
        )
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("TARGET")
                .help("Target domain or IP address")
                .required(true),
        )
        .arg(
            Arg::new("dns-server")
                .short('d')
                .long("dns-server")
                .value_name("DNS_SERVER")
                .help("Custom DNS server IP (optional)"),
        )
        .arg(
            Arg::new("threads")
                .short('T')
                .long("threads")
                .value_name("THREADS")
                .help("Number of threads (default: 10)")
                .default_value("10"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("DNS query timeout in seconds (default: 5)")
                .default_value("5"),
        )
        .get_matches();

    let config = EnumConfig {
        wordlist: matches.get_one::<String>("wordlist").unwrap().to_string(),
        target: matches.get_one::<String>("target").unwrap().to_string(),
        dns_server: matches.get_one::<String>("dns-server").map(|s| s.to_string()),
        threads: matches
            .get_one::<String>("threads")
            .unwrap()
            .parse()
            .expect("Invalid thread count"),
        timeout: matches
            .get_one::<String>("timeout")
            .unwrap()
            .parse()
            .expect("Invalid timeout value"),
    };

    println!("{}", "=================================".blue().bold());
    println!("{}", "DNS Subdomain Enumeration Tool".green().bold());
    println!("{}", "=================================".blue().bold());
    
    // Resolve target if it's an IP
    let domain = resolve_target(&config.target);
    println!("{} {}\n", "[*] Target domain:".cyan(), domain.yellow());
    
    if let Some(ref dns) = config.dns_server {
        println!("{} {}", "[*] Using DNS server:".cyan(), dns.yellow());
    }
    
    println!("{} {}", "[*] Threads:".cyan(), config.threads);
    println!("{} {}s\n", "[*] Timeout:".cyan(), config.timeout);
    
    // Load wordlist
    let words = load_wordlist(&config.wordlist);
    println!("{} {} words loaded\n", "[*] Wordlist:".cyan(), words.len());
    
    // Start enumeration
    println!("{}\n", "[*] Starting enumeration...".green());
    let results = enumerate_subdomains(domain, words, &config);
    
    // Display results
    display_results(&results);
}

fn resolve_target(target: &str) -> String {
    // Check if target is an IP address
    if let Ok(ip) = IpAddr::from_str(target) {
        println!("{} Performing reverse DNS lookup...", "[*]".cyan());
        
        let resolver = match Resolver::from_system_conf() {
            Ok(r) => r,
            Err(_) => Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap(),
        };
        
        match resolver.reverse_lookup(ip) {
            Ok(response) => {
                if let Some(name) = response.iter().next() {
                    let domain = name.to_string();
                    let domain = domain.trim_end_matches('.');
                    println!("{} Resolved {} to {}", "[+]".green(), ip, domain.yellow());
                    return domain.to_string();
                }
            }
            Err(e) => {
                println!("{} Failed to resolve IP: {}", "[!]".red(), e);
                println!("{} Please provide a domain name instead", "[!]".red());
                std::process::exit(1);
            }
        }
    }
    
    // It's already a domain
    target.to_string()
}

fn load_wordlist(path: &str) -> Vec<String> {
    let file = File::open(path).expect("Failed to open wordlist file");
    let reader = BufReader::new(file);
    
    reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn enumerate_subdomains(domain: String, words: Vec<String>, config: &EnumConfig) -> Vec<SubdomainResult> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let words = Arc::new(words);
    let total = words.len();
    let processed = Arc::new(Mutex::new(0));
    
    let mut handles = vec![];
    let chunk_size = (total + config.threads - 1) / config.threads;
    
    for i in 0..config.threads {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, total);
        
        if start >= total {
            break;
        }
        
        let words_chunk = words.clone();
        let results_clone = results.clone();
        let domain_clone = domain.clone();
        let config_clone = config.clone();
        let processed_clone = processed.clone();
        
        let handle = thread::spawn(move || {
            let resolver = create_resolver(&config_clone);
            
            for j in start..end {
                let subdomain = format!("{}.{}", words_chunk[j], domain_clone);
                
                match resolver.lookup_ip(&subdomain) {
                    Ok(response) => {
                        let ips: Vec<IpAddr> = response.iter().collect();
                        if !ips.is_empty() {
                            let result = SubdomainResult {
                                subdomain: subdomain.clone(),
                                ips: ips.clone(),
                            };
                            
                            println!("{} {} -> {:?}", 
                                "[+]".green().bold(), 
                                subdomain.yellow(), 
                                ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ").cyan()
                            );
                            
                            results_clone.lock().unwrap().push(result);
                        }
                    }
                    Err(_) => {
                        // Subdomain doesn't exist or timeout
                    }
                }
                
                let mut p = processed_clone.lock().unwrap();
                *p += 1;
                if *p % 100 == 0 {
                    print!("\r{} Progress: {}/{}", "[*]".cyan(), *p, total);
                    use std::io::{self, Write};
                    io::stdout().flush().unwrap();
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("\r{} Progress: {}/{}   ", "[*]".cyan(), total, total);
    
    let mut final_results = results.lock().unwrap().clone();
    final_results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    final_results
}

fn create_resolver(config: &EnumConfig) -> Resolver {
    if let Some(ref dns_server) = config.dns_server {
        if let Ok(ip) = IpAddr::from_str(dns_server) {
            let socket = SocketAddr::new(ip, 53);
            let name_server = trust_dns_resolver::config::NameServerConfig {
                socket_addr: socket,
                protocol: trust_dns_resolver::config::Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            };
            
            let mut resolver_config = ResolverConfig::new();
            resolver_config.add_name_server(name_server);
            
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(config.timeout);
            opts.attempts = 2;
            
            return Resolver::new(resolver_config, opts).unwrap();
        }
    }
    
    // Use system resolver
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(config.timeout);
    opts.attempts = 2;
    
    match Resolver::from_system_conf() {
        Ok(mut r) => {
            // Can't easily modify system resolver opts, so return as-is
            r
        }
        Err(_) => Resolver::new(ResolverConfig::default(), opts).unwrap(),
    }
}

fn display_results(results: &[SubdomainResult]) {
    println!("\n{}", "=================================".blue().bold());
    println!("{}", "Enumeration Results".green().bold());
    println!("{}", "=================================".blue().bold());
    
    if results.is_empty() {
        println!("{} No subdomains found", "[!]".yellow());
        return;
    }
    
    println!("{} Found {} subdomains:\n", "[+]".green().bold(), results.len());
    
    for result in results {
        println!("  {} {}", 
            result.subdomain.yellow().bold(),
            result.ips.iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
                .cyan()
        );
    }
    
    println!("\n{} Enumeration complete!", "[+]".green().bold());
}
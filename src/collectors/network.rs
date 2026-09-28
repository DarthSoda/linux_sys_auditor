use crate::collector::Collector;
use crate::error::AuditError;
use crate::output::table::{
    print_active_connections_table, print_network_context_table, print_routing_table,
};

use serde::Serialize;

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::net::Ipv4Addr;

#[derive(Serialize, Debug)]
pub struct route_data {
    pub iface: String,
    pub destination: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl route_data {
    fn build() -> route_data {
        route_data {
            iface: String::from("No Entries found!"),
            destination: Ipv4Addr::new(127, 0, 0, 1),
            gateway: Ipv4Addr::new(127, 0, 0, 1),
            mask: Ipv4Addr::new(127, 0, 0, 1),
        }
    }
}
#[derive(Serialize, Debug)]
pub struct NetworkStatus {
    pub hostname: String,
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub arpcache: Vec<Ipv4ArpEntries>,
    pub dns: Vec<Ipv4Addr>,
    pub network_activity: Vec<NetConnection>,
    pub route_info: Vec<route_data>,
    // can be derived from route_info
    // look for local address values.
    // present all the non 0.0.0.0 values.
    //ip_address

    //dhcp enabled: bool
    //dhcp servers: Vec<ipv4addr>
    //active_directory: bool
    //investigate /etc/host
}

#[derive(Serialize, Debug)]
pub struct NetConnection {
    pub protocol: String,
    pub local_address: Ipv4Addr,
    pub local_port: u16,
    pub remote_address: Ipv4Addr,
    pub remote_port: u16,
    pub uid: u32,
}

impl NetConnection {
    fn build(protocol: String) -> NetConnection {
        if protocol.contains("tcp") {
            let default = NetConnection {
                local_address: Ipv4Addr::new(127, 0, 0, 1),
                local_port: 1337,
                remote_address: Ipv4Addr::new(127, 0, 0, 1),
                remote_port: 1337,
                uid: 1337,
                protocol: String::from("TCP"),
            };
            return default;
        } else {
            let default = NetConnection {
                local_address: Ipv4Addr::new(127, 0, 0, 1),
                local_port: 1337,
                remote_address: Ipv4Addr::new(127, 0, 0, 1),
                remote_port: 1337,
                uid: 1337,
                protocol: String::from("UDP"),
            };
            return default;
        }
    }
}

#[derive(Serialize, Debug)]
pub struct Ipv4ArpEntries {
    pub ip_address: Ipv4Addr,
    mac_address: String,
    device_id: String,
}

impl Ipv4ArpEntries {
    fn build() -> Ipv4ArpEntries {
        let default = Ipv4ArpEntries {
            ip_address: Ipv4Addr::new(127, 0, 0, 1),
            mac_address: String::from("00:00:00:00:00:00"),
            device_id: String::from("N0 Arp Entries"),
        };

        default
    }
}

//pub struct IdentityCollector;
pub struct NetworkCollector;

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "Current Network Context"
    }
    //println!("\n{}", "🔍 User Context Audit Complete".bold());

    fn collect(&self) -> Result<Box<dyn erased_serde::Serialize>, AuditError> {
        // Example parsing logic
        //let user_context = get_user_context();
        let network_context = get_network_context();
        Ok(Box::new(network_context))
    }

    fn print_table(&self) {
        // Collect the typed struct directly, then pass it by reference
        // to the table formatter
        let network_context = get_network_context();
        print_network_context_table(&network_context);

        // Immediately follow it with the detailed 6-column socket table
        print_active_connections_table(&network_context);

        print_routing_table(&network_context);
    }
}

fn get_network_context() -> NetworkStatus {
    let hostname_request = get_hostname();
    let arpcache_request = get_arpcache();
    let mut dns_request = get_dnsservers();

    let tcp_connection_request = get_activeconnections("/proc/net/tcp".to_string());
    let udp_connection_request = get_activeconnections("/proc/net/udp".to_string());
    let connection_requests =
        combine_connection_data(tcp_connection_request, udp_connection_request);
    let route_data_request = get_routedata();

    let route_data = match route_data_request {
        Ok(inner_value) => inner_value,
        _ => {
            let default_instance = route_data::build();
            let mut default_vec = Vec::new();
            default_vec.push(default_instance);
            default_vec
        }
    };

    let hostname = match hostname_request {
        Ok(inner_value) => inner_value.to_string(),
        Err(_) => "Cannot read /proc/sys/kernel/hostname".to_string(),
    };

    let arpcache = match arpcache_request {
        Ok(inner_value) => inner_value,
        Err(_) => {
            let default_instance = Ipv4ArpEntries::build();
            let mut default_vec = Vec::new();
            default_vec.push(default_instance);
            default_vec
        }
    };

    if dns_request.is_empty() {
        //let mut result = Vec::new();
        //result.push(String::from("No DNS info discovered!"));
        //dns_request = Vec::new();
        //dns_request.push(String::from("No DNS info discovered!"));
        dns_request.push(Ipv4Addr::new(127, 0, 0, 1));
    }

    let network_activity = match connection_requests {
        Ok(inner_value) => inner_value,
        Err(_) => {
            let default_instance = NetConnection::build("TCP".to_string());
            let mut default_vec = Vec::new();
            default_vec.push(default_instance);
            default_vec
        }
    };

    //let copy_network_activity = network_activity.clone();

    let infered_ipv4_addresses = infer_ipv4_addresses(&network_activity);

    //let route_info_request = route_data::build();

    //println!("INfered complete: {:#?}", infered_ipv4_addresses);

    //println!("{:#?}", network_activity);

    NetworkStatus {
        hostname,
        arpcache,
        dns: dns_request,
        network_activity,
        route_info: route_data,
        ipv4_addresses: infered_ipv4_addresses,
    }
}

fn infer_ipv4_addresses(network_data: &Vec<NetConnection>) -> Vec<Ipv4Addr> {
    //let mut internal_ips: Vec<Ipv4Addr> = Vec::new();

    let shitty_ip_one = Ipv4Addr::new(127, 0, 0, 1);
    let shitty_ip_two = Ipv4Addr::new(0, 0, 0, 0);
    //let mut non_zero_ips: Vec<Ipv4Addr> = network_data
    let mut internal_ips: Vec<Ipv4Addr> = network_data
        .iter()
        .filter(|ip| ip.local_address != shitty_ip_one && ip.local_address != shitty_ip_two)
        .map(|ip| ip.local_address.clone())
        .collect();

    internal_ips.sort();
    internal_ips.dedup();

    if internal_ips.is_empty() {
        let mut default_value = Vec::new();
        default_value.push(Ipv4Addr::new(0, 0, 0, 0));
        return default_value;
    }

    internal_ips
}

fn get_hostname() -> Result<String, &'static str> {
    let mut hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .map_err(|_| "Cannot read /proc/sys/kernel/hostname")?;

    Ok(hostname.trim().to_string())
}

// all the errors are not flushed out, what lets the user know you cant read
// the file if that happens..... it just turns the default entry we created .
fn get_arpcache() -> Result<Vec<Ipv4ArpEntries>, std::io::Error> {
    let file = File::open("/proc/net/arp")?;
    let reader = BufReader::new(file);

    let mut arp_cache: Vec<Ipv4ArpEntries> = Vec::new();

    let line = String::new();

    // iterate over lines
    for line in reader.lines().skip(1) {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Standard /proc/net/arp has 6 columns (IP, HW_type, Flags, Mac, Mask, Device).
        if parts.len() < 6 {
            let default_instance = Ipv4ArpEntries::build();
            arp_cache.push(default_instance);

            return Ok(arp_cache);
        }

        let ip_address = parts[0]
            .parse::<Ipv4Addr>()
            .ok()
            .expect("IP FORMAT NEVER FAILS IN /proc/net/arp");
        let mac_address = parts[3].to_string();
        let device_id = parts[5].to_string();

        //arp_cache.device_id.push
        let new_instance = Ipv4ArpEntries {
            ip_address,
            mac_address,
            device_id,
        };

        arp_cache.push(new_instance);
    }

    if arp_cache.is_empty() {
        let default_instance = Ipv4ArpEntries::build();
        arp_cache.push(default_instance);
        return Ok(arp_cache);
    }
    Ok(arp_cache)
}

//fn get_dnsservers() -> Vec<String> {
fn get_dnsservers() -> Vec<Ipv4Addr> {
    // Check standard resolv.conf, or fallback to systemd-resolved stub/runtime paths
    let paths = [
        "/etc/resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
    ];

    for path in &paths {
        if let Ok(content) = fs::read_to_string(path) {
            let servers: Vec<Ipv4Addr> = content
                //let servers: Vec<String> = content
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with("nameserver") {
                        trimmed.split_whitespace().nth(1)?.parse::<Ipv4Addr>().ok()
                        //trimmed.split_whitespace().nth(1)?.parse::<String>().ok()
                    } else {
                        None
                    }
                })
                .collect();

            if !servers.is_empty() {
                return servers;
            }
        }
    }

    Vec::new()
}

//utility
fn parse_hex(addr_hex: &str) -> Option<(Ipv4Addr)> {
    // Parse hex IP (e.g., "0100007F" -> 127.0.0.1)
    // /proc/net/tcp uses native/little-endian byte ordering for IPs
    let ip_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let local_ip = Ipv4Addr::from(ip_u32.to_le_bytes());

    Some(local_ip)
}

//utility
fn parse_hex_socket(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;

    // Parse hex port (e.g., "0050" -> 80)
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // Parse hex IP (e.g., "0100007F" -> 127.0.0.1)
    // /proc/net/tcp uses native/little-endian byte ordering for IPs
    let ip_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let local_ip = Ipv4Addr::from(ip_u32.to_le_bytes());

    Some((local_ip, port))
}

//fn get_activeconnections(protocol: String) -> Result<Vec<NetConnection>, std::io::Error> {
fn get_activeconnections(path: String) -> Result<Vec<NetConnection>, std::io::Error> {
    let protocol = if path.contains("tcp") {
        String::from("TCP")
    } else {
        String::from("UDP")
    };

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let connections = reader
        .lines()
        .skip(1) // Skip the header row
        .filter_map(|line| line.ok()) // Safely drop any I/O errors per line
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();

            //Destructure exactly what we need using slice pattern matching
            //Index 1 is local, Index 2 is remote, index 7 corresponds with UID
            if let [_, local_raw, remote_raw, _, _, _, _, uid_raw, ..] = parts.as_slice() {
                let (local_address, local_port) = parse_hex_socket(local_raw)?;
                let (remote_address, remote_port) = parse_hex_socket(remote_raw)?;
                let uid = uid_raw.parse::<u32>().ok()?;

                Some(NetConnection {
                    local_address,
                    local_port,
                    remote_address,
                    remote_port,
                    uid,
                    protocol: protocol.clone(),
                })
            } else {
                None
            }
        })
        .collect(); // Collects directly into Vec<TcpConnection>
    Ok(connections)
}

//utility
fn combine_connection_data(
    tcp_data: Result<Vec<NetConnection>, std::io::Error>,
    udp_data: Result<Vec<NetConnection>, std::io::Error>,
) -> Result<Vec<NetConnection>, std::io::Error> {
    tcp_data.and_then(|mut vec1| {
        udp_data.map(|vec2| {
            vec1.extend(vec2);
            vec1
        })
    })
}

fn get_routedata() -> Result<Vec<route_data>, std::io::Error> {
    // 1. Open the file
    let file = File::open("/proc/net/route")?;

    // 2. Wrap it in a BufReader
    let reader = BufReader::new(file);

    let mut route_data: Vec<route_data> = Vec::new();

    // 3. Iterate over the lines lazily
    for line in reader.lines().skip(1) {
        // Each 'line' is a Result<String, io::Error>
        let line = line?;

        let parts: Vec<&str> = line.split_whitespace().collect();

        let iface = parts[0].to_string();
        let fallback = Ipv4Addr::new(127, 0, 0, 1);
        let destination_request = parse_hex(parts[1]);
        let destination = destination_request.unwrap_or(fallback);
        let gateway_request = parse_hex(parts[2]);
        let gateway = gateway_request.unwrap_or(fallback);
        let mask_request = parse_hex(parts[7]);
        let mask = mask_request.unwrap_or(fallback);

        let instance = route_data {
            iface,
            destination,
            gateway,
            mask,
        };

        route_data.push(instance);

        //println!("wtf: {:#?}", instance);
    }

    Ok(route_data)
    //unimplemented!()
}

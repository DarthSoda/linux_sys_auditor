use crate::collectors::identity::{CurrentUserContext, DANGEROUS_GROUPS};
use crate::collectors::network::NetworkStatus;

use colored::Colorize;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, Table};

//pub fn print_context_table(user_context: &CurrentUserContext) {
pub fn print_user_context_table(user_context: &CurrentUserContext) {
    let mut table = Table::new();

    table
        .load_style(UTF8_FULL.with_rounded_corners())
        .set_header(vec![
            Cell::new("User Context").add_attribute(Attribute::Bold),
            Cell::new("Value").add_attribute(Attribute::Bold),
        ]);

    table.add_row(vec![
        Cell::new("Username"),
        Cell::new(&user_context.username).fg(Color::Cyan),
    ]);

    table.add_row(vec![
        Cell::new("EUID"),
        Cell::new(user_context.euid.to_string()),
    ]);

    table.add_row(vec![
        Cell::new("Null Password"),
        Cell::new(if user_context.null_passwd {
            "True"
        } else {
            "False"
        }),
    ]);

    // 2. Groups (Joined and conditionally colored)
    // Build a HashSet for quick lookups
    let dangerous_set: std::collections::HashSet<&str> = DANGEROUS_GROUPS.iter().copied().collect();

    // Map over the groups and apply colors individually

    //let colored_groups: Vec<String> = ctx
    let colored_groups: Vec<String> = user_context
        .groups
        .iter()
        .map(|group| {
            if dangerous_set.contains(group.as_str()) {
                // Highlight dangerous groups in red and bold
                group.red().bold().to_string()
            } else {
                // Dim standard groups
                group.dimmed().to_string()
            }
        })
        .collect();

    // Join the pre-colored strings
    let groups_str = colored_groups.join(", ");

    // Pass the string containing the embedded ANSI codes directly to the cell
    table.add_row(vec![Cell::new("Groups"), Cell::new(groups_str)]);

    println!("{table}");
}

pub fn print_network_context_table(network_context: &NetworkStatus) {
    let mut table = Table::new();

    table
        .load_style(UTF8_FULL.with_rounded_corners())
        .set_header(vec![
            Cell::new("Network Context").add_attribute(Attribute::Bold),
            Cell::new("Value").add_attribute(Attribute::Bold),
        ]);

    // if we add more hostname enumeration we will have to return a vec struct
    // ala cart prepare the future candidate for function formatting_vectors
    table.add_row(vec![
        Cell::new("Hostname"),
        Cell::new(&network_context.hostname),
    ]);

    // 1. Iterate over the vector
    // 2. Map each Ipv4Addr to a String using .to_string()
    // 3. Collect them into a new Vec<String>

    // format inferred ip address
    let string_ips: Vec<String> = network_context
        .ipv4_addresses
        .iter()
        .map(|ip| ip.to_string())
        .collect();

    let display_str = string_ips.join("\n");
    //let collective_ipv4_addresses = network_context.ipv4_addresses.join(", ");

    table.add_row(vec![Cell::new("Ip Address"), Cell::new(display_str)]);

    // format arp entries
    let valid_arp_ips: Vec<String> = network_context
        .arpcache
        .iter()
        // Standard map converts every entry into a String
        .map(|entry| entry.ip_address.to_string())
        .collect();

    let display_arp_ips = valid_arp_ips.join("\n");

    table.add_row(vec![Cell::new("Arp Entries"), Cell::new(display_arp_ips)]);

    // format DNS ips
    let valid_dns_ips: Vec<String> = network_context
        .dns
        .iter()
        .map(|entry| entry.to_string())
        .collect();

    // FIX: Collapse the Vec<String> into a single String
    let display_dns = valid_dns_ips.join("\n");

    table.add_row(vec![Cell::new("DNS Entries"), Cell::new(display_dns)]);

    // format route information

    println!("{table}");

    //println!("{:#?}", network_context.route_info);
}

// Pass the strongly typed data object by immutable reference[cite: 1]
pub fn print_active_connections_table(network_context: &NetworkStatus) {
    // Access the vector of structs
    let connections = &network_context.network_activity;

    // Return early if there are no connections to prevent printing an empty header
    if connections.is_empty() {
        return;
    }

    let mut table = Table::new();

    table
        .load_style(UTF8_FULL.with_rounded_corners())
        .set_header(vec![
            Cell::new("Protocol").add_attribute(Attribute::Bold),
            Cell::new("Local Address").add_attribute(Attribute::Bold),
            Cell::new("Local Port").add_attribute(Attribute::Bold),
            Cell::new("Remote Address").add_attribute(Attribute::Bold),
            Cell::new("Remote Port").add_attribute(Attribute::Bold),
            Cell::new("UID").add_attribute(Attribute::Bold),
        ]);

    // Iterate sequentially over the vector of NetConnection structs
    for conn in connections {
        table.add_row(vec![
            Cell::new(&conn.protocol),
            // Convert Ipv4Addr and numeric types to Strings for comfy-table compatibility[cite: 1]
            Cell::new(conn.local_address.to_string()),
            Cell::new(conn.local_port.to_string()),
            Cell::new(conn.remote_address.to_string()),
            Cell::new(conn.remote_port.to_string()),
            Cell::new(conn.uid.to_string()),
        ]);
    }

    println!("\n[*] Active Network Connections:");
    println!("{table}"); // Render the completed table to the terminal[cite: 1]
}

// provide the struct and field and it will take a vector string
// and return a String with vector values combined into one!
// this ia candidate for a generic value
// the struct type should be a generic value
//fn formatting_vectors(struct_type:, field_name: String) -> String {

pub fn print_routing_table(network_context: &NetworkStatus) {
    let mut table = Table::new();

    // Apply the standard styling and bold headers
    table
        .load_style(UTF8_FULL.with_rounded_corners())
        .set_header(vec![
            Cell::new("Interface").add_attribute(Attribute::Bold),
            Cell::new("Destination").add_attribute(Attribute::Bold),
            Cell::new("Gateway").add_attribute(Attribute::Bold),
            Cell::new("Mask").add_attribute(Attribute::Bold),
        ]);

    // FIX: Target the specific vector field inside the NetworkStatus struct[cite: 1]
    for route in &network_context.route_info {
        table.add_row(vec![
            Cell::new(&route.iface),
            // Convert strongly-typed Ipv4Addr objects to strings
            Cell::new(route.destination.to_string()),
            Cell::new(route.gateway.to_string()),
            Cell::new(route.mask.to_string()),
        ]);
    }

    // Explicitly print the finished table to standard output
    println!("\n[*] Active Routing info");
    println!("{table}");
}

fn formatting_vectors() -> String {
    // 1. Iterate over the vector
    // 2. Map each Ipv4Addr to a String using .to_string()
    // 3. Collect them into a new Vec<String>

    unimplemented!()
}

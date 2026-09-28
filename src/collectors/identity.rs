use crate::collector::Collector;
use crate::error::AuditError;
use crate::output::table::print_user_context_table;
//use serde::Serialize;
use serde::Serialize;

//get_user_context
use std::ffi::CStr;
use std::fs::{self, File};

use std::io::{self, BufRead, BufReader, Error};
use uzers::all_groups;
use uzers::os::unix::GroupExt;

// used to "check" for vulnerable groups
use std::collections::HashSet;

// list of groups that can be exploited
pub const DANGEROUS_GROUPS: &[&str] = &[
    "root",
    "sudo",
    "wheel",
    "docker",
    "lxd",
    "lxc",
    "libvirt",
    "libvirt-qemu",
    "disk",
    "kmem",
    "mem",
    "kcore",
    "staff",
    "bin",
    "system",
    "daemon",
    "shadow",
    "adm",
    "system-journal",
    "pcap",
    "wireshark",
];

#[derive(Debug, Serialize)]
pub struct CurrentUserContext {
    pub username: String,
    pub euid: u32,
    pub groups: Vec<String>,
    pub null_passwd: bool,
}

pub struct IdentityCollector;

impl Collector for IdentityCollector {
    fn name(&self) -> &'static str {
        "Current User Context"
    }
    //println!("\n{}", "🔍 User Context Audit Complete".bold());

    fn collect(&self) -> Result<Box<dyn erased_serde::Serialize>, AuditError> {
        // Example parsing logic
        let user_context = get_user_context();
        Ok(Box::new(user_context))
    }

    fn print_table(&self) {
        // Collect the typed struct directly, then pass it by reference
        // to the table formatter
        let user_context = get_user_context();
        print_user_context_table(&user_context);
    }
}

pub fn get_user_context() -> CurrentUserContext {
    // get euid via libc call
    let euid = unsafe { libc::getuid() };

    let pw = unsafe { libc::getpwuid(euid) };

    let mut null_passwd: bool = false;

    // null password check
    if pw.is_null() {
        null_passwd = true;
    }

    let current_user = unsafe { CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned() };

    let username = current_user.clone();
    let mut nss_groups: Vec<String> = self::network_group_grab(username);
    let mut user_groups: Vec<String> = self::local_gid_grab();
    user_groups.append(&mut nss_groups);
    user_groups.sort();
    user_groups.dedup();

    //println!("{:#?}", user_groups);

    let identity = CurrentUserContext {
        username: current_user.to_string(),
        euid,
        //hostname,
        groups: user_groups,
        null_passwd,
    };

    identity
}

// grabs global group info (applicable to active directory if connected)
fn network_group_grab(username: String) -> Vec<String> {
    //println!("safely received data: {}", username);

    let mut group_data: Vec<String> = Vec::new();

    for group in unsafe { all_groups() } {
        let group_name = group.name().to_string_lossy();
        let members = group.members();

        // If members is a Vec<String>, we can use `.contains()`.
        // We must pass `username` as a reference using `&`
        let user_group_check = members.iter().any(|member| member == username.as_str());

        // Only print groups that have explicit members assigned
        if !members.is_empty() && user_group_check {
            //println!("Group: {} | Explicit Members: {:?}", group_name, members);
            // to_string_lossy returns a Cow, so into_owned() converts it to a String
            group_data.push(group_name.into_owned());
        }
    }

    if group_data.is_empty() {
        return Vec::new(); // A cleaner way to return an empty Vec
    }

    //println!("NSS Groups {:#?}", group_data);
    group_data
}

// grabs local group info (useful as well ;)
fn local_gid_grab() -> Vec<String> {
    let mut groups: Vec<String> = Vec::new();

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            // Target the "Groups:" line specifically for supplementary groups
            if let Some(rest) = line.strip_prefix("Groups:") {
                let names: Vec<String> = rest
                    .split_whitespace()
                    .filter_map(|gid_str| gid_str.parse::<libc::gid_t>().ok())
                    .filter_map(|gid| unsafe {
                        let grp = libc::getgrgid(gid);
                        if grp.is_null() {
                            None
                        } else {
                            CStr::from_ptr((*grp).gr_name)
                                .to_str()
                                .ok()
                                .map(|s| s.to_string())
                        }
                    })
                    .collect();

                groups = names;

                // Break early since we found the supplementary groups
                break;
            }
        }
    }

    //println!("LOCAL GROUPS{:#?}", groups);
    // returns solid local group info
    groups
}

pub fn check_dangerous_groups(user_groups: &[String]) -> Vec<String> {
    // Build a HashSet for O(1) lookups
    let dangerous_set: HashSet<&str> = DANGEROUS_GROUPS.iter().copied().collect();

    // Filter the user's groups to find any matches
    user_groups
        .iter()
        .filter(|group| dangerous_set.contains(group.as_str()))
        .cloned()
        .collect()
}

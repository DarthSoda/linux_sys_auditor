Linux Sys Auditor
Linux Sys Auditor is a stealthy, modular situational awareness and system auditing tool designed for Linux environments. Written in Rust, it acts as a defensive system auditor and configuration compliance checker. The application is built to gather deep host-level telemetry—such as identity context, network configurations, and account privileges—while maintaining a minimal execution footprint.

By leveraging the Rust Collector pattern, the tool easily extends to support new data sources and outputs structured data suitable for both human analysts and automated security pipelines.

Key Features
Stealth-First Enumeration: Gathers system context quietly by reading directly from in-memory pseudo-filesystems (/proc, /sys) and utilizing direct libc system calls. This approach produces zero disk I/O activity and avoids spawning child processes, effectively bypassing execve telemetry and standard process-spawning logs.

Modular Architecture (The Collector Pattern): Employs a trait-based extensibility model where each data category is an independent module adhering to a shared Collector trait. This allows the main orchestration loop to execute checks sequentially and handle errors without panicking.

Dual Output Modes: Integrates seamlessly into workflows with dual presentation layers:

Human-Readable: Renders clean, color-coded terminal tables using comfy-table for immediate visual analysis.

Machine-Readable: Outputs structured JSON via serde_json for direct ingestion into SIEMs, CI/CD checks, or automated pipelines.

Robust Data Modeling: Parses complex system files into strongly typed Rust structs (e.g., converting hex values in /proc/net/tcp to Ipv4Addr), ensuring data validity at parse time.

Data Collection Domains

The tool groups metrics into functional domains to organize the auditing process:
Identity & Context: Gathers the current username, EUID, and hostname via system calls and /proc/sys/kernel/hostname. It maps user group memberships and flags dangerous or sensitive groups (e.g., root, sudo, docker, wheel) for potential privilege escalation risks.

System Accounts: Parses /etc/passwd and /etc/group directly to enumerate existing system users and identify accounts with interactive shells, avoiding the noise of executing standard utilities.

Network Intelligence: Extracts active routing tables, ARP entries, and open network connections by cleanly parsing /proc/net/route, /proc/net/arp, and /proc/net/tcp.

Host Activity: Audits running processes by traversing /proc/[pid]/ and analyzes system authentication configurations (like /etc/nsswitch.conf and /etc/sssd/sssd.conf) to non-intrusively detect Active Directory or LDAP integrations.

Usage
Linux Sys Auditor utilizes clap for command-line argument parsing, allowing users to toggle between presentation formats.

ToDo

Command line flags

Networking Context Info ( not %100 )

Local System User discovery / enumeration ( user processes maps, SUID files, group membership)

System Enumeration ( kernel version )

Host Activity module

Project Structure
Following idiomatic Rust workspace conventions, the codebase cleanly separates low-level data parsing from the presentation layer:
src/main.rs: Orchestrates the execution loop and handles CLI parsing.
src/collector.rs: Defines the core shared Collector trait.
src/collectors/: Houses the independent data gathering modules (identity.rs, network.rs, accounts.rs, etc.).
src/output/: Contains the presentation logic, separating terminal rendering (table.rs) and JSON serialization (json.rs) from data collection.
src/error.rs: Centralizes domain-specific error handling via thiserror for graceful degradation on restricted paths.

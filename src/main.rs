use crate::collector::Collector;
use crate::collectors::identity::IdentityCollector;
use crate::collectors::network::NetworkCollector;
//use crate::output::table::{self, print_context_table};
//Assume you have these built out
// use crate::collectors::network::NetworkCollector;
// use crate::collectors::activity::ActivityCollector;
//use crate::output::table;

pub mod collector;
pub mod collectors;
pub mod error;
pub mod output;

fn main() {
    //1. Build the vector of dynamically dispatched trait objects
    //let collectors: Vec<Box<dyn Collector>> = vec![Box::new(IdentityCollector)];
    let collectors: Vec<Box<dyn Collector>> =
        vec![Box::new(IdentityCollector), Box::new(NetworkCollector)];

    // Simulating a CLI argument switch (true = table, false = json)
    let output_as_table = true;

    // Iterate sequentially over the collectors
    for collector in collectors {
        println!("[*] Running: {}", collector.name());
        if output_as_table {
            // Trigger the internal table formatter (no type casting needed!)
            collector.print_table();
        } else {
            // Machine-readable JSON output
            match collector.collect() {
                Ok(data) => {
                    let json = serde_json::to_string_pretty(&data).unwrap();
                    println!("{}", json);
                }
                Err(err) => {
                    eprintln!("[!] Error collecting {}: {:?}", collector.name(), err);
                }
            }
        }
    }

    //println!("Hello, world!");
}

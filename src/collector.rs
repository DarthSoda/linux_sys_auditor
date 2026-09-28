//use crate::error::AuditError;
use crate::error::AuditError;

pub trait Collector {
    // Human-readable name of the audit check
    fn name(&self) -> &'static str;

    // Runs the check and returns structured, serializable data
    fn collect(&self) -> Result<Box<dyn erased_serde::Serialize>, AuditError>;

    // Executes the dedicated comfy-table redeerer for this specific module
    fn print_table(&self);
}

//! Processor and memory: the details engine (`details`), which reads the processor through
//! CPUID and Windows, the memory modules and board through the firmware's SMBIOS table, and
//! the live sampler engine (`monitor::run`) behind the CPU and memory graphs. Both read as
//! the current user and change nothing on the PC.
pub mod cpuid;
pub mod details;
pub mod monitor;
pub mod smbios;
pub mod topology;

pub use details::{details, Details, DetailsOptions};

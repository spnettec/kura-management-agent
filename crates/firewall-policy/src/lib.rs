//! Parse and compile rules from the original Kura firewall renderer.
//! Authorization and durable original-operation records belong to the caller.
mod clause;
mod compile;
mod layout;
pub mod netlink;
pub mod receipt;
pub mod transport;
pub mod witness;

pub use clause::{canonical_clause, compile_clause};
pub use compile::{CompiledChain, CompiledTable, compile_layout};
pub use layout::{Declaration, Layout, Row, Table, parse_observed, parse_rendered};

pub const DUMP_LIMIT: usize = 512 * 1024;

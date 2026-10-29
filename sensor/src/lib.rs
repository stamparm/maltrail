//! Maltrail's sensor: packet capture, trail matching, the detection heuristics and event
//! logging, in Rust.
//!
//! It reads the same `maltrail.conf` and trail set as the Maltrail server and writes events
//! the server parses. See `docs/ARCHITECTURE.md` for how the pieces fit together and
//! `docs/BEHAVIOUR.md` for compatibility with the server, the detections, design decisions
//! and limitations.

pub mod addr;
pub mod config;
pub mod event;
pub mod fasthash;
pub mod heuristics;
pub mod ignore;
pub mod lru;
pub mod meta;
pub mod metrics;
pub mod output;
pub mod packet;
pub mod process;
pub mod protocols;
pub mod pyre;
pub mod selftest;
pub mod settings;
mod settings_gen;
pub mod smallstr;
pub mod state;
pub mod stats;
pub mod testkit;
pub mod throttle;
pub mod trails;
pub mod trailupdate;
pub mod whitelist;
pub mod worker;

pub mod capture;
pub mod colorized;

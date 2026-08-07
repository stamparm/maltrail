//! Maltrail sensor — Rust implementation of the packet-processing hot path.
//!
//! Behaviour is defined by the Python sensor in this same repository (`sensor.py` and
//! `core/`); every module documents the Python function it reproduces. See
//! `docs/PORTING_MAP.md` for the full mapping and `docs/COMPATIBILITY.md` for the
//! deliberate differences.

pub mod addr;
pub mod config;
pub mod event;
pub mod fasthash;
pub mod heuristics;
pub mod ignore;
pub mod lru;
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

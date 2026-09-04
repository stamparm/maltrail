//! Packet capture: libpcap live handles (with Linux `PACKET_FANOUT`) and offline pcap
//! replay. Mirrors the handle setup in `sensor.py:init()`.

pub mod fanout;
pub mod srcfanout;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::config::{Config, FanoutMode};

/// One capture source owned by exactly one worker.
pub enum Handle {
    Live(Box<pcap::Capture<pcap::Active>>),
    Offline(Box<pcap::Capture<pcap::Offline>>),
}

/// A captured packet: the pcap timestamp plus a borrowed view of the bytes.
pub struct Captured<'a> {
    pub sec: u64,
    pub usec: u32,
    pub caplen: u32,
    pub len: u32,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub enum CaptureError {
    Pcap(pcap::Error),
    Fanout(fanout::FanoutError),
    NoSuchDevice(String),
    Permission(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Pcap(e) => write!(f, "{e}"),
            CaptureError::Fanout(e) => write!(f, "{e}"),
            CaptureError::NoSuchDevice(d) => write!(f, "no such device '{d}'"),
            CaptureError::Permission(m) => write!(f, "permission problem occurred ('{m}')"),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<pcap::Error> for CaptureError {
    fn from(e: pcap::Error) -> CaptureError {
        let text = e.to_string();
        if text.contains("permitted") || text.contains("Permission denied") {
            CaptureError::Permission(text)
        } else if text.contains("No such device") {
            CaptureError::NoSuchDevice(text)
        } else {
            CaptureError::Pcap(e)
        }
    }
}

/// What actually happened while opening a live handle, for the startup diagnostics.
pub struct LiveHandleInfo {
    pub datalink: i32,
    pub fanout_group: Option<u16>,
    pub fanout_mode: FanoutMode,
    pub fanout_flags: u32,
}

impl Handle {
    /// Open one live capture handle and, when requested, join it to the fanout group.
    ///
    /// A requested-but-unavailable fanout is a hard error: falling back to independent
    /// sockets would deliver every packet to every worker (duplicate detections), which is
    /// worse than refusing to start.
    pub fn open_live(
        cfg: &Config,
        interface: &str,
        fanout_group: Option<u16>,
    ) -> Result<(Handle, LiveHandleInfo), CaptureError> {
        let device = pcap::Device::from(interface);
        let mut builder = pcap::Capture::from_device(device)?
            .snaplen(cfg.capture_snaplen as i32)
            .promisc(true)
            .timeout(cfg.capture_timeout_ms);
        if cfg.capture_buffer_size > 0 {
            builder = builder.buffer_size(cfg.capture_buffer_size.min(i32::MAX as u64) as i32);
        }
        if cfg.capture_immediate {
            builder = builder.immediate_mode(true);
        }
        let mut cap = builder.open()?;

        let mut flags = 0u32;
        if cfg.capture_fanout_defrag {
            flags |= fanout::PACKET_FANOUT_FLAG_DEFRAG;
        }
        // A fanout group is a Linux packet-socket concept, and the descriptor it needs comes from
        // a Unix-only trait. config.rs already refuses the option elsewhere; this keeps the call
        // out of the non-Linux builds entirely.
        #[cfg(target_os = "linux")]
        if let Some(group) = fanout_group {
            fanout::join(cap.as_raw_fd(), group, cfg.capture_fanout_mode, flags).map_err(CaptureError::Fanout)?;
        }
        #[cfg(not(target_os = "linux"))]
        if let Some(group) = fanout_group {
            return Err(CaptureError::Fanout(fanout::join(0, group, cfg.capture_fanout_mode, flags).unwrap_err()));
        }

        if !cfg.capture_filter.is_empty() {
            // optimize=true, matching pcapy's default
            cap.filter(&cfg.capture_filter, true)?;
        }

        let datalink = cap.get_datalink().0;
        // Non-blocking reads + an explicit poll() in the worker. A BLOCKING pcap_next_ex can
        // park inside libpcap well past the configured timeout (the TPACKET_V3 block-retire
        // timeout does not bound every code path), which would stop a worker from ever noticing
        // a shutdown request - the sensor would then have to be SIGKILLed and would lose its
        // final metrics and condensed-event flush.
        let cap = cap.setnonblock()?;
        Ok((
            Handle::Live(Box::new(cap)),
            LiveHandleInfo { datalink, fanout_group, fanout_mode: cfg.capture_fanout_mode, fanout_flags: flags },
        ))
    }

    /// Open a pcap file for offline replay.
    pub fn open_offline(path: &Path) -> Result<Handle, CaptureError> {
        let cap = pcap::Capture::from_file(path)?;
        Ok(Handle::Offline(Box::new(cap)))
    }

    pub fn datalink(&self) -> i32 {
        match self {
            Handle::Live(c) => c.get_datalink().0,
            Handle::Offline(c) => c.get_datalink().0,
        }
    }

    pub fn is_offline(&self) -> bool {
        matches!(self, Handle::Offline(_))
    }

    /// Apply a BPF filter. `sensor.py` only does this for live handles; exposed for both so
    /// the parity harness can mirror a capture filter offline when asked to.
    pub fn set_filter(&mut self, filter: &str) -> Result<(), CaptureError> {
        match self {
            Handle::Live(c) => c.filter(filter, true)?,
            Handle::Offline(c) => c.filter(filter, true)?,
        }
        Ok(())
    }

    /// Blocking read of the next packet. `Ok(None)` means a capture timeout (live) or
    /// end-of-file (offline); use [`Handle::stats`] to tell them apart.
    pub fn next_packet(&mut self) -> Result<Option<Captured<'_>>, pcap::Error> {
        let packet = match self {
            Handle::Live(c) => c.next_packet(),
            Handle::Offline(c) => c.next_packet(),
        };
        match packet {
            Ok(p) => Ok(Some(Captured {
                sec: p.header.ts.tv_sec as u64,
                usec: p.header.ts.tv_usec as u32,
                caplen: p.header.caplen,
                len: p.header.len,
                data: p.data,
            })),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The selectable descriptor of a live handle, for `poll(2)`.
    ///
    /// Needed because a blocking `pcap_next_ex` can park inside libpcap for far longer than the
    /// configured timeout on some kernels, which would keep a worker from ever noticing a
    /// shutdown request. The worker therefore runs the handle non-blocking and waits on this
    /// descriptor itself.
    ///
    /// Npcap hands out a Windows event HANDLE rather than a selectable descriptor, so there is
    /// nothing to poll there and this returns None - which the worker already treats as "no
    /// readiness signal available" and falls back to a timed read. The non-blocking-plus-poll
    /// arrangement is an optimisation over that, not a requirement. `i32` rather than `RawFd` so
    /// the signature is the same on both.
    pub fn selectable_fd(&self) -> Option<i32> {
        #[cfg(unix)]
        match self {
            Handle::Live(c) => Some(c.as_raw_fd()),
            Handle::Offline(_) => None,
        }
        #[cfg(not(unix))]
        None
    }

    /// Live capture statistics `(received, dropped, if_dropped)`.
    pub fn stats(&mut self) -> Option<(u32, u32, u32)> {
        match self {
            Handle::Live(c) => c.stats().ok().map(|s| (s.received, s.dropped, s.if_dropped)),
            Handle::Offline(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn write_tiny_pcap(path: &Path, linktype: u32, packets: &[(u32, Vec<u8>)]) {
        use std::io::Write;
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
        f.write_all(&2u16.to_le_bytes()).unwrap();
        f.write_all(&4u16.to_le_bytes()).unwrap();
        f.write_all(&0i32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&65535u32.to_le_bytes()).unwrap();
        f.write_all(&linktype.to_le_bytes()).unwrap();
        for (ts, data) in packets {
            f.write_all(&ts.to_le_bytes()).unwrap();
            f.write_all(&0u32.to_le_bytes()).unwrap();
            f.write_all(&(data.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&(data.len() as u32).to_le_bytes()).unwrap();
            f.write_all(data).unwrap();
        }
    }

    #[test]
    fn offline_replay_reads_timestamps_and_bytes() {
        let dir = std::env::temp_dir().join("mt-capture-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiny.pcap");
        let pkt = vec![0xaa; 32];
        write_tiny_pcap(&path, 1, &[(1700000000, pkt.clone()), (1700000001, pkt.clone())]);

        let mut h = Handle::open_offline(&path).unwrap();
        assert_eq!(h.datalink(), 1);
        assert!(h.is_offline());
        let first = h.next_packet().unwrap().expect("one packet");
        assert_eq!(first.sec, 1700000000);
        assert_eq!(first.data.len(), 32);
        let second = h.next_packet().unwrap().expect("two packets");
        assert_eq!(second.sec, 1700000001);
        assert!(h.next_packet().unwrap().is_none(), "EOF");
        assert!(h.stats().is_none());
    }

    #[test]
    fn missing_pcap_file_is_an_error() {
        assert!(Handle::open_offline(Path::new("/nonexistent/none.pcap")).is_err());
    }

    #[test]
    fn offline_handles_support_bpf_filters() {
        let dir = std::env::temp_dir().join("mt-capture-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("filter.pcap");
        write_tiny_pcap(&path, 1, &[(1, vec![0u8; 60])]);
        let mut h = Handle::open_offline(&path).unwrap();
        assert!(h.set_filter("ip").is_ok());
        assert!(h.set_filter("not a valid filter !!!").is_err());
    }
}

//! Linux `PACKET_FANOUT` configuration for an activated libpcap handle.
//!
//! libpcap on Linux opens an `AF_PACKET` socket and (with a buffer size set) uses the
//! `TPACKET_V3` memory-mapped ring. After activation the socket is already bound to the
//! interface, which is exactly when `PACKET_FANOUT` must be set. Every worker opens its
//! own handle and joins the same group, so the kernel flow-hashes the interface's traffic
//! across the workers instead of delivering every packet to every socket.
//!
//! This reproduces `pcapy-ng`'s `set_fanout()`:
//! `setsockopt(fd, SOL_PACKET, PACKET_FANOUT, (group & 0xffff) | (type << 16))`.

use std::os::unix::io::RawFd;

use crate::capture::srcfanout::{source_hash_program, SockFilter};
use crate::config::FanoutMode;

/// `linux/if_packet.h`
const PACKET_FANOUT: libc::c_int = 18;
/// `PACKET_FANOUT_FLAG_DEFRAG` — ask the kernel to reassemble IP fragments before hashing,
/// so all fragments of a datagram reach the same worker.
pub const PACKET_FANOUT_FLAG_DEFRAG: u32 = 0x8000;
/// `PACKET_FANOUT_FLAG_ROLLOVER`
pub const PACKET_FANOUT_FLAG_ROLLOVER: u32 = 0x1000;
/// `PACKET_FANOUT_DATA` - installs the program for a `PACKET_FANOUT_CBPF` group.
const PACKET_FANOUT_DATA: libc::c_int = 22;

#[derive(Debug)]
pub enum FanoutError {
    NotPacketSocket(i32),
    SetSockOpt(std::io::Error),
    /// The group was joined but the kernel would not take the distribution program. Reported
    /// rather than ignored: the group is live in CBPF mode with no program attached, which is not
    /// a configuration to keep running in.
    SetProgram(std::io::Error),
}

impl std::fmt::Display for FanoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FanoutError::NotPacketSocket(domain) => write!(
                f,
                "capture fd is not an AF_PACKET socket (SO_DOMAIN={domain}); PACKET_FANOUT needs a live Linux capture"
            ),
            FanoutError::SetSockOpt(e) => write!(f, "setsockopt(SOL_PACKET, PACKET_FANOUT) failed: {e}"),
            FanoutError::SetProgram(e) => write!(
                f,
                "setsockopt(SOL_PACKET, PACKET_FANOUT_DATA) failed: {e} (source-affine fanout needs PACKET_FANOUT_CBPF, Linux 4.5+)"
            ),
        }
    }
}

impl std::error::Error for FanoutError {}

/// Confirm the descriptor really is an `AF_PACKET` socket before poking `SOL_PACKET`.
fn check_packet_socket(fd: RawFd) -> Result<(), FanoutError> {
    let mut domain: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is owned by the live pcap handle for the duration of this call, and
    // `domain`/`len` are a correctly sized out-parameter pair for SO_DOMAIN.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        // An offline pcap has no socket at all; report it the same way.
        return Err(FanoutError::NotPacketSocket(-1));
    }
    if domain != libc::AF_PACKET {
        return Err(FanoutError::NotPacketSocket(domain));
    }
    Ok(())
}

/// Join `fd` to the fanout group. `flags` may carry `PACKET_FANOUT_FLAG_*`.
pub fn join(fd: RawFd, group: u16, mode: FanoutMode, flags: u32) -> Result<(), FanoutError> {
    check_packet_socket(fd)?;
    let arg: libc::c_int = ((group as u32 & 0xffff) | ((mode.kernel_value() | flags) << 16)) as libc::c_int;
    // SAFETY: `arg` is a live c_int of the size the kernel expects for PACKET_FANOUT, and
    // `fd` is the activated capture socket. Failure is reported, never ignored.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_FANOUT,
            &arg as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(FanoutError::SetSockOpt(std::io::Error::last_os_error()));
    }

    // CBPF carries no distribution of its own - the group demuxes by whatever program is attached,
    // and with none attached every packet goes to worker 0. So this is part of joining, not an
    // optional extra, and a failure here is a failure to join.
    if mode == FanoutMode::Source {
        attach_program(fd, &source_hash_program())?;
    }
    Ok(())
}

/// `struct sock_fprog` from `linux/filter.h`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Install the classic-BPF distribution program on an already-joined CBPF group.
fn attach_program(fd: RawFd, prog: &[SockFilter]) -> Result<(), FanoutError> {
    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    // SAFETY: `fprog` points at `prog`, which outlives this call, and its length is the
    // instruction count the kernel expects. The kernel copies the program in and verifies it.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_FANOUT_DATA,
            &fprog as *const SockFprog as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(FanoutError::SetProgram(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// A stable per-interface group id: `(pid + interface index) & 0xffff`, matching
/// `sensor.py`. Two sensors on one host therefore get different groups unless the operator
/// pins one with `CAPTURE_FANOUT_GROUP`.
pub fn default_group(interface_index: usize) -> u16 {
    // SAFETY: getpid() is always safe.
    let pid = unsafe { libc::getpid() } as u32;
    ((pid.wrapping_add(interface_index as u32)) & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn rejects_a_non_packet_socket() {
        // A UDP socket must be refused rather than silently "succeeding".
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = join(sock.as_raw_fd(), 1234, FanoutMode::Hash, 0).unwrap_err();
        assert!(matches!(err, FanoutError::NotPacketSocket(_)), "{err}");
        assert!(err.to_string().contains("AF_PACKET"));
    }

    #[test]
    fn rejects_a_plain_file_descriptor() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let err = join(file.as_raw_fd(), 1, FanoutMode::Hash, 0).unwrap_err();
        assert!(matches!(err, FanoutError::NotPacketSocket(-1)), "{err}");
    }

    #[test]
    fn argument_encoding_matches_pcapy_ng() {
        // (group & 0xffff) | (type << 16)
        let group: u32 = 0x1234;
        let arg = (group & 0xffff) | ((FanoutMode::Hash.kernel_value() | PACKET_FANOUT_FLAG_DEFRAG) << 16);
        assert_eq!(arg, 0x8000_1234);
        let arg = (group & 0xffff) | (FanoutMode::Lb.kernel_value() << 16);
        assert_eq!(arg, 0x0001_1234);
        let arg = (group & 0xffff) | (FanoutMode::Cpu.kernel_value() << 16);
        assert_eq!(arg, 0x0002_1234);
    }

    #[test]
    fn default_group_is_stable_within_a_process() {
        assert_eq!(default_group(0), default_group(0));
        assert_ne!(default_group(0), default_group(1));
    }
}

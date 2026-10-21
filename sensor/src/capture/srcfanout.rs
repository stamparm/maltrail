//! A classic-BPF program that distributes packets by SOURCE ADDRESS, for `PACKET_FANOUT_CBPF`.
//!
//! `PACKET_FANOUT_HASH` splits by flow. The scan heuristics count by source, and a scanner walking
//! ephemeral ports is a new flow on every probe, so its evidence is scattered across every worker
//! and none of them reaches the threshold. Measured over the corpus in
//! `tests/multi_worker_parity.rs`: 91% of single-worker heuristic alerts survive at 2 workers, 87%
//! at 4, 66% at 8 - and 100% at every count once the same traffic is distributed by source.
//!
//! Classic BPF rather than eBPF on purpose: `PACKET_FANOUT_CBPF` takes a `sock_fprog` through
//! `setsockopt`, so there is no `bpf()` syscall, no `CAP_BPF`, no libbpf and no compiled object to
//! ship. The privileges are the ones the sensor already needs to open the capture at all.
//!
//! ## Where the packet starts: asked, not guessed
//!
//! The kernel runs this from `packet_rcv_fanout`, the `ptype_all` handler, and what `skb->data`
//! points at there depends on the direction. On receive `eth_type_trans()` has pulled the
//! link-layer header and it is the network header; on transmit (`dev_queue_xmit_nit`) it is still
//! the Ethernet header. The program used to tell the two apart by the first nibble - 4 or 6 meant
//! "already an IP header" - and an outgoing frame whose destination MAC starts with 0x4 or 0x6 (a
//! good share of real vendor prefixes) read as one. Measured on a veth whose peer was
//! 46:00:00:00:00:01: 1,000 outgoing packets from 40 sources, all on worker 0 of 4; the same run
//! towards 02:00:00:00:00:01 split 250/250/250/250. A host's own traffic towards such a gateway
//! landed on one worker, and its traffic towards anything else on another, so its scan evidence
//! was split between them.
//!
//! So nothing is read at an absolute offset. The kernel's own answers are used instead: the
//! protocol through the `SKF_AD_PROTOCOL` ancillary load (`skb->protocol`), and the addresses
//! relative to `SKF_NET_OFF` (`skb_network_header()`), both of which are the same in either
//! direction and on any link type - Ethernet, `any`, tun. A frame still tagged 802.1Q (the
//! kernel normally untags before `ptype_all`) is followed one tag deep.
//!
//! Anything it cannot parse returns 0. That is deliberately the same worker every time rather than
//! something spread: unparseable traffic is a rounding error next to the traffic that matters, and
//! a stable answer is easier to reason about than a random one.

/// One `struct sock_filter` from `linux/filter.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// linux/bpf_common.h
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;

const BPF_ABS: u16 = 0x20;
const BPF_MEM: u16 = 0x60;

const BPF_RSH: u16 = 0x70;
const BPF_XOR: u16 = 0xa0;

const BPF_JEQ: u16 = 0x10;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Fold a 32-bit value into itself so that addresses differing only in their high half still
/// separate after the kernel's `% num_workers`.
fn emit_mix(out: &mut Vec<SockFilter>) {
    out.push(insn(BPF_ST, 0, 0, 0)); // M[0] = A
    out.push(insn(BPF_ALU | BPF_RSH, 0, 0, 16)); // A >>= 16
    out.push(insn(BPF_LDX | BPF_MEM, 0, 0, 0)); // X = M[0]
    out.push(insn(BPF_ALU | BPF_XOR | BPF_X, 0, 0, 0)); // A ^= X
}

// linux/filter.h: loads at these (negative) offsets read kernel metadata, not packet bytes
const SKF_AD_OFF: u32 = (-0x1000i32) as u32;
const SKF_AD_PROTOCOL: u32 = 0;
const SKF_NET_OFF: u32 = (-0x100000i32) as u32;

/// A = the IPv4 source, `ip_off` bytes past the network header, mixed.
fn emit_v4(out: &mut Vec<SockFilter>, ip_off: u32) {
    out.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_NET_OFF + ip_off + 12));
    emit_mix(out);
    out.push(insn(BPF_RET | BPF_A, 0, 0, 0));
}

/// A = the four words of the IPv6 source, `ip_off` bytes past the network header, XOR-folded, then
/// mixed.
fn emit_v6(out: &mut Vec<SockFilter>, ip_off: u32) {
    out.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_NET_OFF + ip_off + 8));
    for word in 1..4u32 {
        out.push(insn(BPF_ST, 0, 0, 0));
        out.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_NET_OFF + ip_off + 8 + word * 4));
        out.push(insn(BPF_LDX | BPF_MEM, 0, 0, 0));
        out.push(insn(BPF_ALU | BPF_XOR | BPF_X, 0, 0, 0));
    }
    emit_mix(out);
    out.push(insn(BPF_RET | BPF_A, 0, 0, 0));
}

/// Build the program.
///
/// Jump targets are counted in instructions AFTER the jump, so the blocks are laid out first and
/// the header is emitted last with the distances known. Hand-computed offsets in a program this
/// shape are exactly the kind of thing that is wrong once and then wrong forever.
pub fn source_hash_program() -> Vec<SockFilter> {
    // blocks, in the order they will be appended after the 5-instruction header
    let mut v4 = Vec::new();
    emit_v4(&mut v4, 0);
    let mut v6 = Vec::new();
    emit_v6(&mut v6, 0);
    let mut v4_vlan = Vec::new();
    emit_v4(&mut v4_vlan, 4);
    let mut v6_vlan = Vec::new();
    emit_v6(&mut v6_vlan, 4);

    const HEADER: usize = 5;
    let at_v4 = HEADER;
    let at_v6 = at_v4 + v4.len();
    let at_vlan = at_v6 + v6.len();
    let at_v4_vlan = at_vlan + 4; // the VLAN dispatch below is 4 instructions
    let at_v6_vlan = at_v4_vlan + v4_vlan.len();

    // distance from the instruction at index `from` to `to`
    let d = |from: usize, to: usize| -> u8 {
        let delta = to - from - 1;
        debug_assert!(delta <= u8::MAX as usize, "cBPF jump out of range");
        delta as u8
    };

    // Built push-by-push rather than as a vec![] literal: every instruction carries its index in
    // a comment, and the jump distances above are expressed in those indices. A literal would put
    // the numbering and the instructions in different places, which is how a jump target goes
    // wrong once and stays wrong.
    #[allow(clippy::vec_init_then_push)]
    let mut p: Vec<SockFilter> = Vec::with_capacity(HEADER + 64);
    // 0: A = skb->protocol
    p.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_PROTOCOL));
    // 1..3: IPv4 / IPv6 / 802.1Q
    p.push(insn(BPF_JMP | BPF_JEQ, d(1, at_v4), 0, 0x0800));
    p.push(insn(BPF_JMP | BPF_JEQ, d(2, at_v6), 0, 0x86dd));
    p.push(insn(BPF_JMP | BPF_JEQ, d(3, at_vlan), 0, 0x8100));
    // 4: anything else
    p.push(insn(BPF_RET, 0, 0, 0));
    debug_assert_eq!(p.len(), HEADER);

    p.extend(v4);
    p.extend(v6);

    // VLAN dispatch: the network header is the tag, whose inner EtherType sits at 2. The explicit
    // ret #0 matters - without it a tagged frame carrying neither IP version falls straight into
    // the IPv4 block and hashes two bytes of somebody else's header.
    p.push(insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, SKF_NET_OFF + 2));
    p.push(insn(BPF_JMP | BPF_JEQ, d(at_vlan + 1, at_v4_vlan), 0, 0x0800));
    p.push(insn(BPF_JMP | BPF_JEQ, d(at_vlan + 2, at_v6_vlan), 0, 0x86dd));
    p.push(insn(BPF_RET, 0, 0, 0));
    p.extend(v4_vlan);
    p.extend(v6_vlan);

    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A classic-BPF interpreter covering exactly the opcodes `source_hash_program()` emits.
    ///
    /// The program is data that the KERNEL executes, so asserting on the instruction bytes would
    /// only prove it matches whatever I wrote. Running it proves what it computes - and it caught
    /// a VLAN frame carrying neither IP version falling through into the IPv4 block.
    ///
    /// It models the skb as the kernel presents it to the program: `skb->protocol` and the bytes
    /// from the network header on. A load at a plain absolute offset is a test failure - those
    /// bytes are the Ethernet header on transmit and the IP header on receive, which is the bug
    /// this program was rewritten for.
    fn run(prog: &[SockFilter], skb: &(u16, Vec<u8>)) -> u32 {
        let (protocol, pkt) = (skb.0, &skb.1);
        let (mut a, mut x): (u32, u32) = (0, 0);
        let mut m = [0u32; 16];
        let mut pc = 0usize;
        let mut steps = 0;

        let load = |k: u32, len: usize| -> Option<u32> {
            if k == SKF_AD_OFF + SKF_AD_PROTOCOL {
                return Some(u32::from(protocol));
            }
            assert!((SKF_NET_OFF..SKF_AD_OFF).contains(&k), "absolute load at {k:#x}: depends on the direction");
            let off = (k - SKF_NET_OFF) as usize;
            if off.checked_add(len)? > pkt.len() {
                return None;
            }
            Some(match len {
                2 => u32::from(u16::from_be_bytes([pkt[off], pkt[off + 1]])),
                _ => u32::from_be_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]),
            })
        };

        loop {
            steps += 1;
            assert!(steps < 4096, "program did not terminate");
            let i = *prog.get(pc).expect("pc past end of program");
            pc += 1;
            match i.code {
                c if c == BPF_LD | BPF_H | BPF_ABS => {
                    a = match load(i.k, 2) {
                        Some(v) => v,
                        None => return 0,
                    }
                }
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    a = match load(i.k, 4) {
                        Some(v) => v,
                        None => return 0,
                    }
                }
                c if c == BPF_ST => m[i.k as usize] = a,
                c if c == BPF_LDX | BPF_MEM => x = m[i.k as usize],
                c if c == BPF_ALU | BPF_RSH => a >>= i.k,
                c if c == BPF_ALU | BPF_XOR | BPF_X => a ^= x,
                c if c == BPF_JMP | BPF_JEQ => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
                c if c == BPF_RET | BPF_A => return a,
                c if c == BPF_RET => return i.k,
                other => panic!("interpreter does not implement opcode {other:#06x}"),
            }
        }
    }

    fn ipv4(src: [u8; 4]) -> (u16, Vec<u8>) {
        let mut p = vec![0x45u8; 20];
        p[12..16].copy_from_slice(&src);
        (0x0800, p)
    }

    fn ipv6(src: [u8; 16]) -> (u16, Vec<u8>) {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[8..24].copy_from_slice(&src);
        (0x86dd, p)
    }

    /// Still tagged: the network header is the 4-byte tag, then the inner packet.
    fn vlan(inner: (u16, Vec<u8>)) -> (u16, Vec<u8>) {
        let mut p = vec![0x00, 0x64];
        p.extend_from_slice(&inner.0.to_be_bytes());
        p.extend_from_slice(&inner.1);
        (0x8100, p)
    }

    /// THE property. Two packets from one source must reach the same worker no matter what flow
    /// they belong to - that is the whole reason this program exists.
    #[test]
    fn one_source_always_lands_on_one_worker() {
        let prog = source_hash_program();
        for workers in [2u32, 4, 8, 16] {
            let a = run(&prog, &ipv4([10, 0, 0, 7])) % workers;
            // same host, different destination and ports: irrelevant to the answer
            let mut other = ipv4([10, 0, 0, 7]);
            other.1[16..20].copy_from_slice(&[8, 8, 8, 8]);
            assert_eq!(a, run(&prog, &other) % workers, "same source split across workers");
        }
    }

    #[test]
    fn different_sources_are_spread_across_workers() {
        let prog = source_hash_program();
        // a /24 of hosts over 8 workers: every worker must get some, or the program is not a
        // distribution at all and multi-worker capture would serialise onto one thread
        let mut seen = [0usize; 8];
        for host in 1..=254u8 {
            seen[(run(&prog, &ipv4([192, 168, 1, host])) % 8) as usize] += 1;
        }
        assert!(seen.iter().all(|&n| n > 10), "uneven distribution: {seen:?}");
    }

    /// A tag the kernel has not removed leads to the same answer as the untagged packet.
    #[test]
    fn a_tagged_packet_lands_where_the_untagged_one_does() {
        let prog = source_hash_program();
        let bare = ipv4([203, 0, 113, 9]);
        assert_eq!(run(&prog, &bare), run(&prog, &vlan(bare.clone())), "IPv4: VLAN layout disagrees");

        let mut src = [0u8; 16];
        src[0..2].copy_from_slice(&[0x20, 0x01]);
        src[15] = 0xbe;
        let bare6 = ipv6(src);
        assert_eq!(run(&prog, &bare6), run(&prog, &vlan(bare6.clone())), "IPv6: VLAN layout disagrees");
    }

    #[test]
    fn an_ipv6_source_uses_all_sixteen_bytes() {
        let prog = source_hash_program();
        // hosts sharing a /64 differ only in the interface id; if the program folded just the
        // prefix, every host on a subnet would land on one worker - the failure this replaces
        let mut a = [0u8; 16];
        a[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
        let mut b = a;
        a[15] = 1;
        b[15] = 2;
        assert_ne!(run(&prog, &ipv6(a)), run(&prog, &ipv6(b)), "the interface id is ignored");
    }

    #[test]
    fn unparseable_traffic_is_answered_not_crashed() {
        let prog = source_hash_program();
        // NON-ZERO payload on purpose: with zeros, a program that wrongly falls through into the
        // IPv4 block hashes four zero bytes and returns 0 anyway, so the test would pass while the
        // bug it exists for was present. It did, until this fixture was changed.
        let arp = (0x0806u16, vec![0xa5u8; 28]);
        assert_eq!(run(&prog, &arp), 0, "ARP");
        assert_eq!(run(&prog, &vlan(arp.clone())), 0, "tagged ARP must not fall into the IPv4 block");
        assert_eq!(run(&prog, &(0x0800, vec![])), 0, "empty");
        assert_eq!(run(&prog, &(0x0800, vec![0x45])), 0, "one byte of an IPv4 header");
        assert_eq!(run(&prog, &(0x86dd, vec![0x60; 20])), 0, "truncated inside the IPv6 source");
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        let prog = source_hash_program();
        for (i, insn) in prog.iter().enumerate() {
            if insn.code & 0x07 == BPF_JMP {
                for target in [i + 1 + usize::from(insn.jt), i + 1 + usize::from(insn.jf)] {
                    assert!(target < prog.len(), "instruction {i} jumps to {target}, past the end");
                }
            }
        }
        // the kernel rejects a program whose last instruction is not a return
        let last = prog.last().expect("program is empty");
        assert!(last.code & 0x07 == BPF_RET, "program does not end in a return");
        assert!(prog.len() <= 4096, "cBPF programs are capped at 4096 instructions");
    }
}

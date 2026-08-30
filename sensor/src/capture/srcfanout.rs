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
//! ## Where the packet starts, and why the program does not assume
//!
//! The kernel runs this from `packet_rcv_fanout`, which is the `ptype_all` handler - BEFORE
//! `packet_rcv` pushes back to the MAC header. On the receive path `eth_type_trans()` has already
//! pulled the link-layer header, so `skb->data` is expected to be the NETWORK header. That is a
//! statement about kernel internals, and getting it wrong would send every packet to worker 0 -
//! a silent capture failure, which is the worst possible outcome here.
//!
//! So the program does not rely on it. It reads the first nibble: 4 or 6 means it is already
//! looking at an IP header. Otherwise it treats the bytes as a link-layer header and reads the
//! EtherType at offset 12, following one 802.1Q tag if present. Both layouts are exercised by the
//! interpreter tests below, so the program is correct whichever one the kernel presents.
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
const BPF_B: u16 = 0x10;

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

/// A = the IPv4 source at `ip_off`, mixed.
fn emit_v4(out: &mut Vec<SockFilter>, ip_off: u32) {
    out.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, ip_off + 12));
    emit_mix(out);
    out.push(insn(BPF_RET | BPF_A, 0, 0, 0));
}

/// A = the four words of the IPv6 source at `ip_off`, XOR-folded, then mixed.
fn emit_v6(out: &mut Vec<SockFilter>, ip_off: u32) {
    out.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, ip_off + 8));
    for word in 1..4u32 {
        out.push(insn(BPF_ST, 0, 0, 0));
        out.push(insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, ip_off + 8 + word * 4));
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
    // blocks, in the order they will be appended after the 9-instruction header
    let mut v4_net = Vec::new();
    emit_v4(&mut v4_net, 0);
    let mut v6_net = Vec::new();
    emit_v6(&mut v6_net, 0);
    let mut v4_eth = Vec::new();
    emit_v4(&mut v4_eth, 14);
    let mut v6_eth = Vec::new();
    emit_v6(&mut v6_eth, 14);
    let mut v4_vlan = Vec::new();
    emit_v4(&mut v4_vlan, 18);
    let mut v6_vlan = Vec::new();
    emit_v6(&mut v6_vlan, 18);

    const HEADER: usize = 9;
    let at_v4_net = HEADER;
    let at_v6_net = at_v4_net + v4_net.len();
    let at_v4_eth = at_v6_net + v6_net.len();
    let at_v6_eth = at_v4_eth + v4_eth.len();
    let at_vlan = at_v6_eth + v6_eth.len();
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
    // 0: A = first byte
    p.push(insn(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0));
    // 1: A >>= 4  -> IP version, if this is a network header
    p.push(insn(BPF_ALU | BPF_RSH, 0, 0, 4));
    // 2: version 4?
    p.push(insn(BPF_JMP | BPF_JEQ, d(2, at_v4_net), 0, 4));
    // 3: version 6?
    p.push(insn(BPF_JMP | BPF_JEQ, d(3, at_v6_net), 0, 6));
    // 4: not a network header - read the EtherType
    p.push(insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12));
    // 5..7: IPv4 / IPv6 / 802.1Q
    p.push(insn(BPF_JMP | BPF_JEQ, d(5, at_v4_eth), 0, 0x0800));
    p.push(insn(BPF_JMP | BPF_JEQ, d(6, at_v6_eth), 0, 0x86dd));
    p.push(insn(BPF_JMP | BPF_JEQ, d(7, at_vlan), 0, 0x8100));
    // 8: anything else
    p.push(insn(BPF_RET, 0, 0, 0));
    debug_assert_eq!(p.len(), HEADER);

    p.extend(v4_net);
    p.extend(v6_net);
    p.extend(v4_eth);
    p.extend(v6_eth);

    // VLAN dispatch: the inner EtherType sits at 16. The explicit ret #0 matters - without it a
    // tagged frame carrying neither IP version falls straight into the IPv4 block and hashes two
    // bytes of somebody else's header.
    p.push(insn(BPF_LD | BPF_H | BPF_ABS, 0, 0, 16));
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
    fn run(prog: &[SockFilter], pkt: &[u8]) -> u32 {
        let (mut a, mut x): (u32, u32) = (0, 0);
        let mut m = [0u32; 16];
        let mut pc = 0usize;
        let mut steps = 0;

        let load = |off: u32, len: usize| -> Option<u32> {
            let off = off as usize;
            if off.checked_add(len)? > pkt.len() {
                return None;
            }
            Some(match len {
                1 => u32::from(pkt[off]),
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
                c if c == BPF_LD | BPF_B | BPF_ABS => {
                    a = match load(i.k, 1) {
                        Some(v) => v,
                        None => return 0,
                    }
                }
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

    fn ipv4(src: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0x45u8; 20];
        p[12..16].copy_from_slice(&src);
        p
    }

    fn ipv6(src: [u8; 16]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[8..24].copy_from_slice(&src);
        p
    }

    fn ether(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12..14].copy_from_slice(&ethertype.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn vlan(inner: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x64]); // priority/VID
        p.extend_from_slice(&inner.to_be_bytes());
        p.extend_from_slice(payload);
        p
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
            other[16..20].copy_from_slice(&[8, 8, 8, 8]);
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

    /// The layout question the module header is about: the kernel may present the network header
    /// or the link-layer header, and the program must be right either way.
    #[test]
    fn both_packet_layouts_reach_the_same_answer() {
        let prog = source_hash_program();

        let bare = ipv4([203, 0, 113, 9]);
        assert_eq!(run(&prog, &bare), run(&prog, &ether(0x0800, &bare)), "IPv4: layouts disagree");
        assert_eq!(run(&prog, &bare), run(&prog, &vlan(0x0800, &bare)), "IPv4: VLAN layout disagrees");

        let mut src = [0u8; 16];
        src[0..2].copy_from_slice(&[0x20, 0x01]);
        src[15] = 0xbe;
        let bare6 = ipv6(src);
        assert_eq!(run(&prog, &bare6), run(&prog, &ether(0x86dd, &bare6)), "IPv6: layouts disagree");
        assert_eq!(run(&prog, &bare6), run(&prog, &vlan(0x86dd, &bare6)), "IPv6: VLAN layout disagrees");
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
        let arp = [0xa5u8; 28];
        assert_eq!(run(&prog, &ether(0x0806, &arp)), 0, "ARP");
        assert_eq!(run(&prog, &vlan(0x0806, &arp)), 0, "tagged ARP must not fall into the IPv4 block");
        assert_eq!(run(&prog, &[]), 0, "empty");
        assert_eq!(run(&prog, &[0x45]), 0, "one byte of an IPv4 header");
        assert_eq!(run(&prog, &ether(0x0800, &[0x45, 0x00])), 0, "truncated inside the IP header");
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

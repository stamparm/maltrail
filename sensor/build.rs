//! Turn a missing libpcap into a sentence somebody can act on.
//!
//! The sensor links `libpcap`, so without its development package the build dies at the very last
//! step — after compiling every dependency — with:
//!
//! ```text
//! error: linking with `cc` failed: exit status: 1
//!   = note: /usr/bin/ld: cannot find -lpcap: No such file or directory
//! ```
//!
//! preceded by a screen of linker arguments. Nothing in that names a package, and the runtime
//! library being installed (`libpcap0.8`) is not enough — the headers and the `.so` symlink come
//! from `libpcap-dev`. A Raspberry Pi 5 install hit exactly this after a five-minute compile.
//!
//! So the same link is attempted here, first, with a two-line C file, and the failure is reported
//! with the package name for the common distributions.
//!
//! This only WARNS; it never fails the build. The warning lands moments before the linker error
//! it explains, which is enough to be useful, and it means a probe that is wrong about an unusual
//! setup can never block a build that would otherwise have worked. It also stays silent unless it
//! has proven the link impossible with the real compiler: no compiler to probe with, an
//! unrecognised error, or a cross-compile (where the host's libraries say nothing about the
//! target's) all mean it says nothing at all.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MALTRAIL_SKIP_PCAP_CHECK");

    if std::env::var_os("MALTRAIL_SKIP_PCAP_CHECK").is_some() {
        return;
    }
    // Cross-compiling: the host's libpcap tells us nothing about the target's, and probing with
    // the host compiler would reject perfectly good cross builds (the release workflow does two).
    match (std::env::var("HOST"), std::env::var("TARGET")) {
        (Ok(host), Ok(target)) if host != target => return,
        _ => {}
    }

    if pkg_config_reports_libpcap() {
        return;
    }
    if let Verdict::Missing = try_to_link() {
        // One `cargo:warning=` per line; cargo prints each prefixed and highlighted.
        for line in [
            "libpcap cannot be linked -- the link step below will fail with 'cannot find -lpcap'.",
            "The DEVELOPMENT package is required; the runtime library alone (libpcap0.8) is not.",
            "  Debian / Ubuntu / Raspberry Pi OS:  sudo apt-get install libpcap-dev",
            "  RHEL / Fedora:                      sudo dnf install libpcap-devel",
            "  openSUSE / SLES:                    sudo zypper install libpcap-devel",
            "  Alpine: sudo apk add libpcap-dev      Arch: sudo pacman -S libpcap",
            "Or use a prebuilt binary, which needs no toolchain and no headers:",
            "  https://github.com/stamparm/maltrail/releases",
        ] {
            println!("cargo:warning={line}");
        }
    }
}

enum Verdict {
    /// The compiler linked `-lpcap`; nothing to say.
    Fine,
    /// The compiler ran and rejected `-lpcap`.
    Missing,
    /// Could not tell. Say nothing.
    Unknown,
}

/// `pkg-config --exists libpcap`, when pkg-config is present. Cheap and needs no compiler.
fn pkg_config_reports_libpcap() -> bool {
    Command::new("pkg-config").args(["--exists", "libpcap"]).status().map(|s| s.success()).unwrap_or(false)
}

/// Compile and link a trivial program against `-lpcap` with the same compiler rustc will use.
fn try_to_link() -> Verdict {
    let Some(out_dir) = std::env::var_os("OUT_DIR").map(PathBuf::from) else { return Verdict::Unknown };
    let source = out_dir.join("maltrail_pcap_probe.c");
    let binary = out_dir.join("maltrail_pcap_probe.bin");
    // No pcap.h include: this probes the LINKER, and requiring the header would misreport a
    // system where the library is present but the header sits somewhere unusual.
    if std::fs::write(&source, "int main(void) { return 0; }\n").is_err() {
        return Verdict::Unknown;
    }

    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let output = Command::new(&compiler).arg(&source).arg("-lpcap").arg("-o").arg(&binary).output();
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&binary);

    let Ok(output) = output else { return Verdict::Unknown };
    if output.status.success() {
        return Verdict::Fine;
    }
    // Only claim it is missing when the compiler said so about pcap specifically. Any other
    // failure (no C runtime, a sandbox, a broken toolchain) is not ours to diagnose.
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("-lpcap") || stderr.contains("lpcap") || stderr.contains("library not found for -lpcap") {
        Verdict::Missing
    } else {
        Verdict::Unknown
    }
}

// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
//! Compiles libarena (vendor/libarena) and csrc/arena_glue.bpf.c to BPF
//! bitcode with clang and archives them as libarena_c.a in OUT_DIR, which
//! arena-linker finds through the `-L` search path this script exports.
//! Only runs when the target is BPF; host builds (check/doc/test) skip it.
//!
//! Environment (all optional):
//!   LLVM_PREFIX / CLANG      clang with the BPF backend (else `clang` on PATH)
//!   LIBARENA_VMLINUX_H       vmlinux.h for the target kernel; default: generated
//!                            from VMLINUX_BTF (/sys/kernel/btf/vmlinux) with BPFTOOL
//!   LIBBPF_INCLUDE           directory containing bpf/bpf_helpers.h
//!   BPF_STREAM_KFUNC         impl|plain (6.17/6.18 vs newer stream printk kfunc);
//!                            auto-detected from the running kernel when
//!                            LIBARENA_VMLINUX_H is unset
//!   BPF_ARCH_DEFINE          -D__TARGET_ARCH_x86 / arm64 (libarena's map_extra)
//!   BPF_CPU                  v4
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn envv(n: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={n}");
    env::var(n).ok().filter(|v| !v.is_empty())
}

fn run(c: &mut Command) {
    let out = c.output().unwrap_or_else(|e| panic!("cannot run {:?}: {e}", c.get_program()));
    if !out.status.success() {
        panic!("{:?} failed:\n{}", c, String::from_utf8_lossy(&out.stderr));
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=vendor/libarena/libarena/src");
    println!("cargo:rerun-if-changed=vendor/libarena/libarena/include");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("bpf") {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let la = root.join("vendor/libarena/libarena");
    if !la.join("src/common.bpf.c").exists() {
        panic!("libarena sources missing at {}: git submodule update --init", la.display());
    }
    let llvm_bin = envv("LLVM_PREFIX").map(|p| PathBuf::from(p).join("bin"));
    let tool = |name: &str| -> Command {
        match &llvm_bin {
            Some(b) => Command::new(b.join(name)),
            None => Command::new(name),
        }
    };
    let clang = envv("CLANG").map(Command::new).unwrap_or_else(|| tool("clang"));

    // vmlinux.h
    let user_vmlinux = envv("LIBARENA_VMLINUX_H");
    let vmlinux_h = match &user_vmlinux {
        Some(p) => PathBuf::from(p),
        None => {
            let p = out.join("vmlinux.h");
            let btf = envv("VMLINUX_BTF").unwrap_or_else(|| "/sys/kernel/btf/vmlinux".into());
            let bpftool = envv("BPFTOOL").unwrap_or_else(|| "bpftool".into());
            let o = Command::new(&bpftool)
                .args(["btf", "dump", "file", &btf, "format", "c"])
                .output()
                .unwrap_or_else(|e| panic!("cannot run {bpftool} to generate vmlinux.h: {e}; set LIBARENA_VMLINUX_H"));
            if !o.status.success() {
                panic!("bpftool btf dump {btf} failed:\n{}", String::from_utf8_lossy(&o.stderr));
            }
            std::fs::write(&p, o.stdout).unwrap();
            p
        }
    };
    // libbpf headers
    let libbpf_include = envv("LIBBPF_INCLUDE")
        .or_else(|| {
            Command::new("pkg-config")
                .args(["--variable=includedir", "libbpf"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "/usr/include".into());
    if !Path::new(&libbpf_include).join("bpf/bpf_helpers.h").exists() {
        panic!("bpf/bpf_helpers.h not found under {libbpf_include}: install libbpf-dev or set LIBBPF_INCLUDE");
    }
    // knobs
    let stream = envv("BPF_STREAM_KFUNC").unwrap_or_else(|| {
        if user_vmlinux.is_none()
            && std::fs::read_to_string("/proc/kallsyms")
                .map(|s| s.lines().any(|l| l.ends_with(" bpf_stream_vprintk_impl")))
                .unwrap_or(false)
        {
            "impl".into()
        } else {
            "plain".into()
        }
    });
    let arch = envv("BPF_ARCH_DEFINE").unwrap_or_else(|| {
        if env::consts::ARCH == "aarch64" { "-D__TARGET_ARCH_arm64".into() } else { "-D__TARGET_ARCH_x86".into() }
    });
    let cpu = envv("BPF_CPU").unwrap_or_else(|| "v4".into());

    let srcs = [la.join("src/common.bpf.c"), la.join("src/buddy.bpf.c"), root.join("csrc/arena_glue.bpf.c")];
    let mut bcs = Vec::new();
    for src in &srcs {
        let bc = out.join(src.file_stem().unwrap()).with_extension("bc");
        let mut c = Command::new(clang.get_program());
        c.args(["--target=bpfel", &format!("-mcpu={cpu}"), "-O2", "-g", "-DENABLE_ATOMICS_TESTS", &arch])
            .args(["-Wno-incompatible-pointer-types-discards-qualifiers", "-Wno-missing-declarations", "-Wno-macro-redefined"]);
        if stream == "impl" {
            c.arg("-DLIBARENA_RS_STREAM_IMPL");
        }
        c.arg("-include").arg(root.join("csrc/kfunc_compat.h"))
            .arg(format!("-I{}", la.join("include").display()))
            .arg(format!("-I{}", vmlinux_h.parent().unwrap().display()))
            .arg(format!("-I{libbpf_include}"))
            .args(["-emit-llvm", "-c"])
            .arg(src)
            .arg("-o")
            .arg(&bc);
        run(&mut c);
        bcs.push(bc);
    }
    let archive = out.join("libarena_c.a");
    let _ = std::fs::remove_file(&archive);
    let mut ar = tool("llvm-ar");
    ar.arg("rcs").arg(&archive).args(&bcs);
    run(&mut ar);
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:warning=libarena-rs: C side built with vmlinux.h={} stream-kfunc={stream}", vmlinux_h.display());
}

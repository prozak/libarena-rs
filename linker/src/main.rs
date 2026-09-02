// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
//! arena-linker: the `linker-flavor = "bpf"` linker for libarena-rs programs.
//!
//! rustc calls it as `arena-linker <inputs...> -L <dir>... --export-symbols
//! <file> --cpu <cpu> -o <out> [-O3] [--debug]`. Inputs are bitcode objects
//! (`obj-is-bitcode`) and rlibs whose members are bitcode. libarena's C
//! bitcode arrives as `libarena_c.a` in one of the `-L` directories, put
//! there by libarena-rs's build script (rustc's BPF linker flavor drops
//! `-l` requests, so the archive is located by name).
//!
//! Pipeline (identical to the former mk/libarena.mk):
//!   llvm-link everything -> lower_mem.py (+ ARENA_PRE_PASSES)
//!   -> opt internalize(keep list)+globaldce -> force_inline.py
//!   -> opt always-inline+O2 (+ ARENA_POST_PASSES) -> trap_to_ret.py (ret mode)
//!   -> bpf_finalize.py -> llc -> llvm-objcopy (strip EH) -> btf_rename.py
//!
//! Environment: LLVM_PREFIX (tools; else PATH), PYTHON (default python3),
//! TRAP_MODE=throw|ret|auto, TRAP_COOKIE, VOID_GLOBALS=internalize|keep,
//! KEEP_EXTRA (space-separated), ARENA_PRE_PASSES / ARENA_POST_PASSES
//! (colon-separated `script` paths run as `script in.ll out.ll`),
//! ARENA_LINKER_KEEP_TEMPS=1, ARENA_LINKER_VERBOSE=1.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

const SCRIPTS: &[(&str, &str)] = &[
    ("lower_mem.py", include_str!("../scripts/lower_mem.py")),
    ("force_inline.py", include_str!("../scripts/force_inline.py")),
    ("keep_syms.py", include_str!("../scripts/keep_syms.py")),
    ("trap_to_ret.py", include_str!("../scripts/trap_to_ret.py")),
    ("bpf_finalize.py", include_str!("../scripts/bpf_finalize.py")),
    ("btf_rename.py", include_str!("../scripts/btf_rename.py")),
];

struct Opts {
    inputs: Vec<PathBuf>,
    lib_dirs: Vec<PathBuf>,
    export_symbols: Option<PathBuf>,
    output: PathBuf,
    cpu: String,
}

fn die(msg: &str) -> ! {
    eprintln!("arena-linker: {msg}");
    process::exit(1);
}

fn envv(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn verbose() -> bool {
    envv("ARENA_LINKER_VERBOSE").is_some()
}

fn parse_args() -> Opts {
    let mut args: Vec<String> = env::args().skip(1).collect();
    // response files
    let mut expanded = Vec::new();
    for a in args.drain(..) {
        if let Some(f) = a.strip_prefix('@') {
            let text = fs::read_to_string(f).unwrap_or_else(|e| die(&format!("{f}: {e}")));
            expanded.extend(text.split_whitespace().map(String::from));
        } else {
            expanded.push(a);
        }
    }
    let mut o = Opts {
        inputs: vec![],
        lib_dirs: vec![],
        export_symbols: None,
        output: PathBuf::new(),
        cpu: "v4".into(),
    };
    let mut it = expanded.into_iter();
    while let Some(a) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| die("missing argument value"));
        match a.as_str() {
            "-o" => o.output = next().into(),
            "-L" => o.lib_dirs.push(next().into()),
            "-l" => {
                next();
            }
            "--cpu" => o.cpu = next(),
            "--cpu-features" => {
                next();
            }
            "--export-symbols" => o.export_symbols = Some(next().into()),
            "--debug" | "-O0" | "-O1" | "-O2" | "-O3" | "-Os" | "-Oz" => {}
            s if s.starts_with("-L") => o.lib_dirs.push(s[2..].into()),
            s if s.starts_with("-l") => {}
            s if s.starts_with("--cpu=") => o.cpu = s[6..].into(),
            s if s.starts_with('-') => eprintln!("arena-linker: ignoring unknown flag {s}"),
            _ => o.inputs.push(a.into()),
        }
    }
    if o.output.as_os_str().is_empty() {
        die("no -o output");
    }
    o
}

struct Tools {
    bin: Option<PathBuf>,
    python: String,
}

impl Tools {
    fn find() -> Tools {
        let bin = envv("LLVM_PREFIX").map(|p| PathBuf::from(p).join("bin")).or_else(|| {
            Command::new("llvm-config")
                .arg("--bindir")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        });
        Tools { bin, python: envv("PYTHON").unwrap_or_else(|| "python3".into()) }
    }
    fn tool(&self, name: &str) -> Command {
        match &self.bin {
            Some(b) => Command::new(b.join(name)),
            None => Command::new(name),
        }
    }
}

fn run(mut cmd: Command) -> Vec<u8> {
    if verbose() {
        eprintln!("arena-linker: {cmd:?}");
    }
    let out = cmd.output().unwrap_or_else(|e| die(&format!("cannot run {:?}: {e}", cmd.get_program())));
    if !out.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        die(&format!("{:?} failed", cmd.get_program()));
    }
    if verbose() && !out.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    }
    out.stdout
}

fn is_bitcode(p: &Path) -> bool {
    fs::read(p).map(|b| b.starts_with(b"BC\xC0\xDE")).unwrap_or(false)
}

fn is_archive(p: &Path) -> bool {
    fs::read(p).map(|b| b.starts_with(b"!<arch>\n")).unwrap_or(false)
}

/// Extract an ar archive's bitcode members into `dir`.
fn extract(t: &Tools, archive: &Path, dir: &Path) -> Vec<PathBuf> {
    fs::create_dir_all(dir).unwrap();
    let mut c = t.tool("llvm-ar");
    c.arg("x").arg(fs::canonicalize(archive).unwrap()).current_dir(dir);
    run(c);
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| is_bitcode(p))
        .collect();
    v.sort();
    v
}

fn read_lines(p: &Path) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect()
}

fn main() {
    let o = parse_args();
    let t = Tools::find();
    let keep_temps = envv("ARENA_LINKER_KEEP_TEMPS").is_some();
    let tmp = PathBuf::from(format!("{}.arena-linker", o.output.display()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap_or_else(|e| die(&format!("{}: {e}", tmp.display())));
    let scripts = tmp.join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    for (name, body) in SCRIPTS {
        fs::write(scripts.join(name), body).unwrap();
    }
    let script = |n: &str| scripts.join(n);
    let py = |t: &Tools, s: &Path| {
        let mut c = Command::new(&t.python);
        c.arg(s);
        c
    };
    let p = |n: &str| tmp.join(n);

    // ---- gather bitcode -------------------------------------------------
    let mut rust_bcs = Vec::new();
    for (i, inp) in o.inputs.iter().enumerate() {
        if is_bitcode(inp) {
            rust_bcs.push(inp.clone());
        } else if is_archive(inp) {
            rust_bcs.extend(extract(&t, inp, &tmp.join(format!("rlib{i}"))));
        } else if verbose() {
            eprintln!("arena-linker: skipping non-bitcode input {}", inp.display());
        }
    }
    let arena_archive = o
        .lib_dirs
        .iter()
        .map(|d| d.join("libarena_c.a"))
        .find(|p| p.exists())
        .unwrap_or_else(|| die("libarena_c.a not found in any -L directory: is libarena-rs a dependency (its build.rs produces it)?"));
    let arena_bcs = extract(&t, &arena_archive, &tmp.join("arena_c"));
    if rust_bcs.is_empty() || arena_bcs.is_empty() {
        die("no bitcode inputs");
    }

    // libarena's symbols (global and static) stay outlined and, unless
    // void-returning, global.
    let nm = run({
        let mut c = t.tool("llvm-nm");
        c.arg("--defined-only").args(&arena_bcs);
        c
    });
    let mut arena_syms: Vec<String> = String::from_utf8_lossy(&nm)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3 && "TtWw".contains(f[1])).then(|| f[2].to_string())
        })
        .filter(|s| !matches!(s.as_str(), "bpf_arena_memcpy" | "bpf_arena_memcmp" | "bpf_arena_memset" | "memset"))
        .collect();
    arena_syms.sort();
    arena_syms.dedup();
    fs::write(p("arena_syms.txt"), arena_syms.join("\n") + "\n").unwrap();

    // ---- link -----------------------------------------------------------
    run({
        let mut c = t.tool("llvm-link");
        c.args(&rust_bcs).args(&arena_bcs).arg("-o").arg(p("linked.bc"));
        c
    });
    run({
        let mut c = t.tool("llvm-dis");
        c.arg(p("linked.bc")).arg("-o").arg(p("stage0.ll"));
        c
    });

    // ---- keep list ------------------------------------------------------
    let void_globals = envv("VOID_GLOBALS").unwrap_or_else(|| "internalize".into());
    let mut extra: Vec<String> = o.export_symbols.as_deref().map(read_lines).unwrap_or_default();
    extra.extend(envv("KEEP_EXTRA").unwrap_or_default().split_whitespace().map(String::from));
    let keep = run({
        let mut c = py(&t, &script("keep_syms.py"));
        c.arg(p("stage0.ll")).arg("--nm-list").arg(p("arena_syms.txt"));
        if !extra.is_empty() {
            c.arg("--extra").args(&extra);
        }
        if void_globals == "internalize" {
            c.arg("--drop-void-globals");
        }
        c
    });
    let keep: Vec<String> = String::from_utf8_lossy(&keep).split_whitespace().map(String::from).collect();
    fs::write(p("keep.txt"), keep.join("\n") + "\n").unwrap();
    let mut noinline = keep.clone();
    noinline.extend(arena_syms.iter().cloned());
    noinline.sort();
    noinline.dedup();
    fs::write(p("noinline.txt"), noinline.join("\n") + "\n").unwrap();

    // ---- pre-internalize passes -----------------------------------------
    let passes = |var: &str| -> Vec<PathBuf> {
        envv(var).unwrap_or_default().split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect()
    };
    let mut pre = vec![script("lower_mem.py")];
    pre.extend(passes("ARENA_PRE_PASSES"));
    for s in &pre {
        run({
            let mut c = py(&t, s);
            c.arg(p("stage0.ll")).arg(p("stage0.ll"));
            c
        });
    }

    // ---- internalize + globaldce ------------------------------------------
    run({
        let mut c = t.tool("opt");
        for k in &keep {
            c.arg(format!("--internalize-public-api-list={k}"));
        }
        c.arg("--force-remove-attribute=cold")
            .arg("-passes=forceattrs,internalize,globaldce")
            .arg(p("stage0.ll"))
            .arg("-o")
            .arg(p("stage1.bc"));
        c
    });
    run({
        let mut c = t.tool("llvm-dis");
        c.arg(p("stage1.bc")).arg("-o").arg(p("stage1.ll"));
        c
    });

    // ---- force-inline + O2 ------------------------------------------------
    let force_args = run({
        let mut c = py(&t, &script("force_inline.py"));
        c.arg(p("stage1.ll")).arg(p("stage2.ll")).arg(p("noinline.txt"));
        c
    });
    run({
        let mut c = t.tool("opt");
        c.args(String::from_utf8_lossy(&force_args).split_whitespace())
            .arg("-passes=forceattrs,always-inline,globaldce,default<O2>")
            .arg(p("stage2.ll"))
            .arg("-o")
            .arg(p("stage3.bc"));
        c
    });
    run({
        let mut c = t.tool("llvm-dis");
        c.arg(p("stage3.bc")).arg("-o").arg(p("stage3.ll"));
        c
    });
    for s in passes("ARENA_POST_PASSES") {
        run({
            let mut c = py(&t, &s);
            c.arg(p("stage3.ll")).arg(p("stage3.ll"));
            c
        });
    }

    // ---- traps, kfunc tagging ---------------------------------------------
    let cookie = envv("TRAP_COOKIE").unwrap_or_else(|| "0xC0DED".into());
    let mut trap_mode = envv("TRAP_MODE").unwrap_or_else(|| {
        if envv("LIBARENA_VMLINUX_H").is_none() { "auto".into() } else { "throw".into() }
    });
    if trap_mode == "auto" {
        // building for the running kernel: bpf_throw needs JIT exception
        // support, which on x86 means the ORC unwinder
        let orc = Command::new("sh")
            .args(["-c", "zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_UNWINDER_ORC=y'"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let has_config = Path::new("/proc/config.gz").exists();
        trap_mode = if has_config && !orc { "ret".into() } else { "throw".into() };
    }
    if trap_mode == "ret" {
        run({
            let mut c = py(&t, &script("trap_to_ret.py"));
            c.arg(p("stage3.ll")).arg(p("stage3.ll")).arg(&cookie);
            c
        });
    }
    run({
        let mut c = py(&t, &script("bpf_finalize.py"));
        c.arg(p("stage3.ll")).arg(p("final.ll"));
        if trap_mode == "throw" {
            c.arg(format!("--trap-cookie={cookie}"));
        }
        c
    });

    // ---- codegen ------------------------------------------------------------
    run({
        let mut c = t.tool("llc");
        c.arg("-march=bpfel")
            .arg(format!("-mcpu={}", o.cpu))
            .arg("-filetype=obj")
            .arg(p("final.ll"))
            .arg("-o")
            .arg(p("out.o"));
        c
    });
    run({
        let mut c = t.tool("llvm-objcopy");
        c.args([
            "--remove-section=.eh_frame",
            "--remove-section=.rel.eh_frame",
            "--remove-section=.gcc_except_table",
            "--strip-symbol=rust_eh_personality",
        ])
        .arg(p("out.o"))
        .arg(&o.output);
        c
    });
    run({
        let mut c = py(&t, &script("btf_rename.py"));
        c.arg(&o.output);
        c
    });
    if !keep_temps {
        let _ = fs::remove_dir_all(&tmp);
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use blake3::Hasher as Blake3Hasher;
use clap::{Parser, Subcommand};
use ignore::overrides::OverrideBuilder;
use ignore::DirEntry;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};

const MANIFEST_PATH: &str = "__DIRSEAL__/MANIFEST.json";
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIR_MODE: u32 = 0o755;
const FIXED_MTIME: u64 = 0; 

#[derive(Parser, Debug)]
#[command(name = "dirseal", version, about = "dirseal: a deterministic directory packer")] 
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// pack a dir into tar.zst with embedded manifest
    Pack {
        #[arg(default_value = ".")]
        root: PathBuf,
        /// output file or directory. if dir artifact is named by tree hash
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(short = 'l', long, default_value_t = 10)]
        level: i32,
        /// no. of zstd threads (>=1). if multiple we try to use multithreaded compression
        #[arg(short = 't', long, default_value_t = 1)]
        threads: usize,
        #[arg(long, num_args = 0..)]
        include: Vec<String>,
        #[arg(long, num_args = 0..)]
        exclude: Vec<String>,
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        #[arg(long, default_value_t = 12)]
        short: usize,
    },
    /// verify archive's contents against its embedded manifest or a dir
    Verify {
        archive: PathBuf,
        #[arg(long)]
        against: Option<PathBuf>,
    },
    /// diff two sources
    Diff {
        left: PathBuf,
        right: PathBuf,
    },
    /// list entries from an archive from its manifest
    List {
        archive: PathBuf,
    },
    /// compute tree hash for a dir honoring ignore rules
    Hash {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long, num_args = 0..)]
        include: Vec<String>,
        #[arg(long, num_args = 0..)]
        exclude: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EntryKind {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManifestEntry {
    path: String,
    kind: EntryKind,
    size: u64,
    mode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    deterministic: bool,
    archive_format: &'static str,
    compression: &'static str,
    created_epoch_utc: u64,
    root_display: String,
    entries: Vec<ManifestEntry>,
    tree_hash: String,
    options: ManifestOptions,
    tool: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ManifestOptions {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    include: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    exclude: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Pack { root, out, level, threads, include, exclude, manifest_out, short } => {
            let (manifest, artifact_path) = pack_dir(&root, out.as_deref(), level, threads, &include, &exclude, manifest_out.as_deref())?;
            println!("sealed {} entries -> {}", manifest.entries.len(), display_rel(&artifact_path));
            println!("tree hash: {}", &manifest.tree_hash[0..manifest.tree_hash.len().min(short)]);
        }
        Commands::Verify { archive, against } => {
            let embedded = read_manifest_from_archive(&archive)?;
            if let Some(dir) = against {
                let dir_manifest = build_manifest_from_dir(&dir, &embedded.options.include, &embedded.options.exclude)?;
                let diffs = diff_manifests(&embedded, &dir_manifest);
                if diffs.is_empty() {
                    println!("OK: archive matches directory (tree hash {})", &embedded.tree_hash[0..12.min(embedded.tree_hash.len())]);
                } else {
                    print_diffs(&diffs);
                    return Err(anyhow!("mismatch between archive and directory"));
                }
            } else {
                verify_archive_internal(&archive, &embedded)?;
                println!("OK: archive verified against embedded manifest (tree hash {})", &embedded.tree_hash[0..12.min(embedded.tree_hash.len())]);
            }
        }
        Commands::Diff { left, right } => {
            let left_manifest = load_manifest_from_source(&left)?;
            let right_manifest = load_manifest_from_source(&right)?;
            let diffs = diff_manifests(&left_manifest, &right_manifest);
            if diffs.is_empty() {
                println!("No differences ({} == {})", &left_manifest.tree_hash[0..12], &right_manifest.tree_hash[0..12]);
            } else {
                print_diffs(&diffs);
            }
        }
        Commands::List { archive } => {
            let manifest = read_manifest_from_archive(&archive)?;
            for e in &manifest.entries {
                match e.kind {
                    EntryKind::File => println!("F {} {}", e.hash.as_deref().unwrap_or("-"), e.path),
                    EntryKind::Dir => println!("D {: <64} {}", "-", e.path),
                    EntryKind::Symlink => println!("L {: <64} {} -> {}", "-", e.path, e.link_target.as_deref().unwrap_or("?")),
                }
            }
        }
        Commands::Hash { root, include, exclude, json } => {
            let manifest = build_manifest_from_dir(&root, &include, &exclude)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                println!("{}", manifest.tree_hash);
            }
        }
    }
    Ok(())
}

fn display_rel(path: &Path) -> String {
    let cwd = std::env::current_dir().ok();
    if let Some(cwd) = cwd {
        if let Ok(rel) = path.strip_prefix(&cwd) {
            return rel.display().to_string();
        }
    }
    path.display().to_string()
}

fn normalize_sep(s: &str) -> String {
    s.replace('\\', "/")
}

fn now_epoch() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

fn build_manifest_from_dir(root: &Path, include: &[String], exclude: &[String]) -> Result<Manifest> {
    let root = root.canonicalize().with_context(|| format!("canonicalizing {}", root.display()))?;
    let root_display = root.file_name().unwrap_or_else(|| OsStr::new(".")).to_string_lossy().to_string();

    let entries = collect_entries(&root, include, exclude)?;
    let tree_hash = compute_tree_hash(&entries);
    Ok(Manifest {
        version: 1,
        deterministic: true,
        archive_format: "tar",
        compression: "zstd",
        created_epoch_utc: now_epoch(),
        root_display,
        entries,
        tree_hash,
        options: ManifestOptions { include: include.to_vec(), exclude: exclude.to_vec() },
        tool: format!("dirseal {}", env!("CARGO_PKG_VERSION")),
    })
}

fn collect_entries(root: &Path, include: &[String], exclude: &[String]) -> Result<Vec<ManifestEntry>> {
    let mut overrides = OverrideBuilder::new(root);
    // include globs have higher precedence via "!pattern" override semantics
    for inc in include {
        overrides.add(&format!("!{}", inc)).with_context(|| format!("bad include glob: {}", inc))?;
    }
    for exc in exclude {
        overrides.add(exc).with_context(|| format!("bad exclude glob: {}", exc))?;
    }
    let overrides = overrides.build()?;

    let mut walker = WalkBuilder::new(root);
    walker
        .standard_filters(true)
        .hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .overrides(overrides);

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let mut symlinks: Vec<(String, PathBuf)> = Vec::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();

    for result in walker.build() {
        let dent: DirEntry = match result { Ok(d) => d, Err(err) => return Err(anyhow!(err)) };
        let path = dent.path();
        if path == root { continue; }
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = normalize_sep(&rel.to_string_lossy());

        // parent directories are tracked so we can preserve empty dirs
        if let Some(parent) = rel.parent() { if !parent.as_os_str().is_empty() { dirs.insert(normalize_sep(&parent.to_string_lossy())); } }

        let ft = match dent.file_type() { Some(t) => t, None => continue };
        if ft.is_dir() { dirs.insert(rel_str.clone()); continue; }
        if ft.is_symlink() { symlinks.push((rel_str, path.to_path_buf())); continue; }
        if ft.is_file() { files.push((rel_str, path.to_path_buf())); }
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut entries: Vec<ManifestEntry> = Vec::new();

    // add dirs first sorted by BTreeSet
    for d in dirs.into_iter() {
        entries.push(ManifestEntry { path: d, kind: EntryKind::Dir, size: 0, mode: DEFAULT_DIR_MODE, hash: None, link_target: None });
    }

    // symlinks sorted
    symlinks.sort_by(|a, b| a.0.cmp(&b.0));
    for (rel, p) in symlinks.into_iter() {
        let target = fs::read_link(&p).with_context(|| format!("reading symlink {}", p.display()))?;
        let target_str = normalize_sep(&target.to_string_lossy());
        let hash = blake3_hex(target_str.as_bytes());
        entries.push(ManifestEntry { path: rel, kind: EntryKind::Symlink, size: 0, mode: 0o777, hash: Some(hash), link_target: Some(target_str) });
    }

    // files
    for (rel, p) in files.into_iter() {
        let meta = fs::metadata(&p).with_context(|| format!("stat {}", p.display()))?;
        let size = meta.len();
        let hash = hash_file(&p)?;
        entries.push(ManifestEntry { path: rel, kind: EntryKind::File, size, mode: DEFAULT_FILE_MODE, hash: Some(hash), link_target: None });
    }

    Ok(entries)
}

fn blake3_hex(bytes: &[u8]) -> String { blake3::hash(bytes).to_hex().to_string() }

fn hash_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Blake3Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn compute_tree_hash(entries: &[ManifestEntry]) -> String {
    let mut hasher = Blake3Hasher::new();
    let mut lines: Vec<String> = Vec::with_capacity(entries.len());
    for e in entries {
        match e.kind {
            EntryKind::File => {
                lines.push(format!("F {} {}\n", e.hash.as_deref().unwrap_or(""), e.path));
            }
            EntryKind::Dir => {
                lines.push(format!("D {}\n", e.path));
            }
            EntryKind::Symlink => {
                lines.push(format!("L {} {}\n", e.link_target.as_deref().unwrap_or(""), e.path));
            }
        }
    }
    lines.sort();
    for l in lines { hasher.update(l.as_bytes()); }
    hasher.finalize().to_hex().to_string()
}

fn pack_dir(root: &Path, out: Option<&Path>, level: i32, threads: usize, include: &[String], exclude: &[String], manifest_out: Option<&Path>) -> Result<(Manifest, PathBuf)> {
    let manifest = build_manifest_from_dir(root, include, exclude)?;

    let artifact_path = match out {
        Some(p) if p.is_dir() => p.join(format!("dirseal-{}.tar.zst", manifest.tree_hash)),
        Some(p) if p.extension().and_then(|e| e.to_str()) == Some("zst") => p.to_path_buf(),
        Some(p) => p.with_extension("tar.zst"),
        None => PathBuf::from(format!("dirseal-{}.tar.zst", manifest.tree_hash)),
    };

    let parent = artifact_path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create output dir {}", parent.display()))?;
    let file = File::create(&artifact_path).with_context(|| format!("create {}", artifact_path.display()))?;

    let mut encoder = zstd::stream::Encoder::new(file, level).context("init zstd encoder")?;
    if threads > 1 {
        let _ = encoder.multithread(threads as u32);
    }

    let mut builder = tar::Builder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);

    for e in manifest.entries.iter().filter(|e| matches!(e.kind, EntryKind::Dir)) {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(e.mode as u32);
        header.set_mtime(FIXED_MTIME);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Directory);
        builder.append_data(&mut header, Path::new(&e.path), io::empty()).with_context(|| format!("tar add dir {}", e.path))?;
    }

    for e in manifest.entries.iter().filter(|e| matches!(e.kind, EntryKind::Symlink)) {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_mtime(FIXED_MTIME);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Symlink);
        if let Some(target) = &e.link_target {
            header.set_link_name(Path::new(target)).with_context(|| format!("set link name for {}", e.path))?;
        }
        builder.append_data(&mut header, Path::new(&e.path), io::empty()).with_context(|| format!("tar add symlink {}", e.path))?;
    }

    for e in manifest.entries.iter().filter(|e| matches!(e.kind, EntryKind::File)) {
        let src = root.join(&e.path);
        let mut header = tar::Header::new_gnu();
        header.set_mtime(FIXED_MTIME);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(e.mode as u32);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(e.size);
        let mut f = File::open(&src).with_context(|| format!("open {}", src.display()))?;
        builder.append_data(&mut header, Path::new(&e.path), &mut f).with_context(|| format!("tar add file {}", e.path))?;
    }

    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    let mut header = tar::Header::new_gnu();
    header.set_mtime(FIXED_MTIME);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(DEFAULT_FILE_MODE);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(manifest_json.len() as u64);
    builder.append_data(&mut header, Path::new(MANIFEST_PATH), &manifest_json[..]).context("tar add manifest")?;

    let encoder = builder.into_inner().context("finalize tar")?;
    let _file = encoder.finish().context("finalize zstd")?;

    if let Some(path) = manifest_out {
        let out_path = if path.is_dir() { path.join("MANIFEST.json") } else { path.to_path_buf() };
        fs::write(&out_path, &manifest_json).with_context(|| format!("write {}", out_path.display()))?;
    }

    Ok((manifest, artifact_path))
}

fn read_manifest_from_archive(archive: &Path) -> Result<Manifest> {
    let file = File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file).context("zstd decode")?;
    let mut ar = tar::Archive::new(decoder);
    for entry in ar.entries().context("iterate tar entries")? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.as_ref() == Path::new(MANIFEST_PATH) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let manifest: Manifest = serde_json::from_slice(&buf)?;
            return Ok(manifest);
        }
    }
    Err(anyhow!("manifest not found in archive"))
}

fn verify_archive_internal(archive: &Path, manifest: &Manifest) -> Result<()> {
    let file = File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file).context("zstd decode")?;
    let mut ar = tar::Archive::new(decoder);

    let mut map: BTreeMap<String, (EntryKind, Option<String>)> = BTreeMap::new();
    for entry in ar.entries().context("iterate tar entries")? {
        let mut entry = entry?;
        let path = normalize_sep(&entry.path()?.to_string_lossy());
        if path == MANIFEST_PATH { continue; }
        let header = entry.header().clone();
        let kind = match header.entry_type() {
            tar::EntryType::Regular => EntryKind::File,
            tar::EntryType::Directory => EntryKind::Dir,
            tar::EntryType::Symlink => EntryKind::Symlink,
            _ => continue, // skip special types
        };
        let hash = match kind {
            EntryKind::File => {
                let mut hasher = Blake3Hasher::new();
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = entry.read(&mut buf)?;
                    if n == 0 { break; }
                    hasher.update(&buf[..n]);
                }
                Some(hasher.finalize().to_hex().to_string())
            }
            EntryKind::Symlink => {
                let link_name = header.link_name()?.map(|p| normalize_sep(&p.to_string_lossy())).unwrap_or_default();
                Some(blake3_hex(link_name.as_bytes()))
            }
            EntryKind::Dir => None,
        };
        map.insert(path, (kind, hash));
    }

    let manifest_map: BTreeMap<_, _> = manifest
        .entries
        .iter()
        .map(|e| (e.path.clone(), (e.kind.clone(), e.hash.clone())))
        .collect();

    let mut diffs = Vec::new();
    for (p, (k, h)) in &manifest_map {
        match map.get(p) {
            None => diffs.push(format!("missing in archive: {}", p)),
            Some((ak, ah)) => {
                if ak != k || &ah.as_ref().map(|s| s.as_str()) != &h.as_ref().map(|s| s.as_str()) {
                    diffs.push(format!("changed: {}", p));
                }
            }
        }
    }
    for p in map.keys() {
        if !manifest_map.contains_key(p) { diffs.push(format!("extra in archive: {}", p)); }
    }
    if diffs.is_empty() { Ok(()) } else { print_lines(&diffs); Err(anyhow!("verification failed")) }
}

fn print_lines(lines: &[String]) { for l in lines { println!("{}", l); } }

fn load_manifest_from_source(path: &Path) -> Result<Manifest> {
    if path.is_dir() {
        build_manifest_from_dir(path, &[], &[])
    } else {
        read_manifest_from_archive(path)
    }
}

fn diff_manifests(left: &Manifest, right: &Manifest) -> Vec<String> {
    let left_map: BTreeMap<_, _> = left.entries.iter().map(|e| (e.path.clone(), (e.kind.clone(), e.hash.clone()))).collect();
    let right_map: BTreeMap<_, _> = right.entries.iter().map(|e| (e.path.clone(), (e.kind.clone(), e.hash.clone()))).collect();

    let mut diffs: Vec<String> = Vec::new();

    for (p, (rk, rh)) in &right_map {
        match left_map.get(p) {
            None => diffs.push(format!("+ {}", p)),
            Some((lk, lh)) => {
                if lk != rk || lh != rh { diffs.push(format!("~ {}", p)); }
            }
        }
    }
    for p in left_map.keys() {
        if !right_map.contains_key(p) { diffs.push(format!("- {}", p)); }
    }
    diffs
}

fn print_diffs(diffs: &[String]) {
    if diffs.is_empty() { println!("No differences"); return; }
    println!("diff ({} changes):", diffs.len());
    for d in diffs { println!("{}", d); }
}



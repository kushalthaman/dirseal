dirseal is a deterministic directory packer. it turns a directory into a reproducible tar.zst snapshot while honoring `.gitignore` and custom globs, embeds a manifest (with paths and blake3 hashes) and names the artifact by its content tree-hash. i use it for reliable build caching, ci artifacts, content-addressed deploys, and quick verification/diffs.

## installation & usage 

```bash
cargo install --path .
```

```bash
# pack current dir to dirseal-<treehash>.tar.zst
dirseal pack

# if you want to pack with custom globs and output dir
dirseal pack . --out ./artifacts --include "src/**" --exclude "target/**" -l 10 -t 4

# verify archive internally
dirseal verify artifacts/dirseal-<hash>.tar.zst

# or against a directory
dirseal verify artifacts/dirseal-<hash>.tar.zst --against .

# diff two sources
dirseal diff left.tar.zst right.tar.zst
dirseal diff left/ right/
dirseal diff left/ right.tar.zst

# list entries
dirseal list artifacts/dirseal-<hash>.tar.zst

# compute tree hash only
dirseal hash .
```

## determinism

- entries are sorted with normalized `"/"` separators
- Tar headers use fixed mtime (0), uid/gid 0, consistent modes
- manifest excluded from tree hash to avoid recursion

## general notes

- `.gitignore`, global git excludes, and standard ignore files are honored. Use `--include`/`--exclude` to tweak.
- Symlinks are recorded with their target; their hash is the BLAKE3 of the target string.
- Empty directories are preserved.


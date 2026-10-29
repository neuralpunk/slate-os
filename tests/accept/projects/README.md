# Acceptance demo projects

Small projects that `cargo xtask accept` commits into a repository,
clones inside Slate over git's HTTP protocol, builds and runs:

- `c/`: a multi-file C program with a Makefile (threads, math, files).
- `rust/`: a std-only Cargo project with unit tests (threads, processes,
  files); no crates.io dependencies, so the build is deterministic.
- `check.py`: Python with subprocess, threads, JSON and hashlib.

Each prints one line starting with its name and ending in `ok`.

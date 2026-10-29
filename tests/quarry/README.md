# quarry test packages

Package sources for the quarry checks in `cargo xtask test`.
Each directory has a manifest (`QUARRY`) and the tree to package
(`root/`); xtask packs them with the checkout's development key into
signed test repositories (`target/quarry/www/`), which the guest reaches
over HTTP:

- `v1`: hello 1.0 (needs libgreet), libgreet 1, qhello 1.0 (a static
  Linux binary, `abi: linux`, built from `qhello.c` with musl-gcc).
- `v2`: v1 plus hello 1.1 (drops the `hi` link, adds a file).
- `apps`: qapp 1.0 and qbare 1.0, the native program in `qapp-1.0/qapp.c`
  (built with `tools/slate-cc`) declaring the network and nothing, and
  qbad 1.0, which declares a permission Slate doesn't know.
- `bad`: a package changed after it was indexed (SHA-256 mismatch).
- `forged`: an index signed by a key the guest does not trust.

`/test/quarry/` also gets an unsigned package and one signed by the
untrusted key.

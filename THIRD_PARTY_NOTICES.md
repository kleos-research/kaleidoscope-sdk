# Third-party notices

Apache-2.0 covers everything in this repository -- the Rust manager, the Python
package, the TypeScript package, the integration examples, the conformance
probes, the reference goldens and the agent skill. See `LICENSE` and `NOTICE`;
`NOTICE` carries the authoritative statement of scope.

This file covers the third-party software that code carries or depends on. It
does **not** cover the `kscope` memory engine or any other proprietary
object-code payload delivered in a platform package: those are not part of this
repository and are not Apache-2.0. They are not licensed by this repository at
all -- separate terms apply to them, and their own third-party notices travel
with the payload rather than with this file.

Regenerate with `python3 scripts/third_party_notices.py`. `--check` fails if the
committed file has drifted from the manifests.


## Rust -- statically linked into the `kaleidoscope` manager binary

These crates are compiled into the manager executable that ships inside a
platform package, so their object code is redistributed and their attribution
terms bind this project directly. A given build links the subset its platform
selects.

This table is the union over the three shipped target triples
(aarch64-apple-darwin, x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc) of
every non-dev, non-build, non-proc-macro crate reachable from the manager's
root package. Proc-macro and build-dependency crates run at build time and
leave no bytes in the artefact, so they carry no distribution obligation and
are excluded. So do the crates reachable *only* through a proc-macro -- `syn`,
`quote`, `proc-macro2`, `unicode-ident` and the rest of that closure link into
a build-time plugin, never into the executable.

Two exclusions are easy to lose, and losing either produces a table that reads
correct and over-claims. Without `--filter-platform`, `cargo metadata` reports
the union over every platform it knows -- 246 crates -- including `wasi`,
`wasm-bindgen`, `android_system_properties` and, reached through
`uds_windows`, this crate's sole dev-dependency. Without the proc-macro
traversal cut it reports 173, the extra 16 being that build-time closure.
Over-attribution is legally safe and factually wrong, and this preamble makes a
claim about linkage that either set of rows falsifies. Both cuts are the
generator's, not a hand edit; regenerate rather than prune.

**Open obligation, recorded here so the platform-package build can see it.**
Several of these crates are MIT, BSD-2/3-Clause or ISC, and those licences
require their notice to travel with every copy of the object code -- not merely
with the source repository. A committed markdown file in a source tree does not
reach a user who installs a platform package. The engine carries the notices it
has inside the executable (`kscope licences`) and says in that same output that
its own Rust dependency notices are not embedded yet -- so it has the identical
open obligation, not a solution to copy. The `kaleidoscope` manager has no
equivalent command at all. Whoever assembles a platform package must place this
attribution beside or inside the manager binary. This file is the content; it is
not yet the delivery, on either side of the boundary.


| Crate | Version | Licence | Upstream |
| --- | --- | --- | --- |
| `aes` | 0.8.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/block-ciphers |
| `async-broadcast` | 0.5.1 | MIT OR Apache-2.0 | https://github.com/smol-rs/async-broadcast |
| `async-channel` | 2.5.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/async-channel |
| `async-executor` | 1.14.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/async-executor |
| `async-fs` | 1.6.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/async-fs |
| `async-io` | 1.13.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/async-io |
| `async-lock` | 2.8.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/async-lock |
| `async-task` | 4.7.1 | Apache-2.0 OR MIT | https://github.com/smol-rs/async-task |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT | https://github.com/smol-rs/atomic-waker |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | https://github.com/marshallpierce/rust-base64 |
| `base64ct` | 1.8.3 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats |
| `bitflags` | 1.3.2 | MIT/Apache-2.0 | https://github.com/bitflags/bitflags |
| `bitflags` | 2.13.1 | MIT OR Apache-2.0 | https://github.com/bitflags/bitflags |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| `block-padding` | 0.3.3 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| `blocking` | 1.6.2 | Apache-2.0 OR MIT | https://github.com/smol-rs/blocking |
| `byteorder` | 1.5.0 | Unlicense OR MIT | https://github.com/BurntSushi/byteorder |
| `cbc` | 0.1.2 | MIT OR Apache-2.0 | https://github.com/RustCrypto/block-modes |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | https://github.com/rust-lang/cfg-if |
| `chrono` | 0.4.45 | MIT OR Apache-2.0 | https://github.com/chronotope/chrono |
| `cipher` | 0.4.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| `concurrent-queue` | 2.5.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/concurrent-queue |
| `const-oid` | 0.9.6 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats/tree/master/const-oid |
| `core-foundation` | 0.10.1 | MIT OR Apache-2.0 | https://github.com/servo/core-foundation-rs |
| `core-foundation-sys` | 0.8.7 | MIT OR Apache-2.0 | https://github.com/servo/core-foundation-rs |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| `crossbeam-utils` | 0.8.22 | MIT OR Apache-2.0 | https://github.com/crossbeam-rs/crossbeam |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| `der` | 0.7.10 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats/tree/master/der |
| `digest` | 0.10.7 | MIT OR Apache-2.0 | https://github.com/RustCrypto/traits |
| `enumflags2` | 0.7.12 | MIT OR Apache-2.0 | https://github.com/meithecatte/enumflags2 |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT | https://github.com/indexmap-rs/equivalent |
| `event-listener` | 2.5.3 | Apache-2.0 OR MIT | https://github.com/smol-rs/event-listener |
| `event-listener` | 5.4.2 | Apache-2.0 OR MIT | https://github.com/smol-rs/event-listener |
| `event-listener-strategy` | 0.5.4 | Apache-2.0 OR MIT | https://github.com/smol-rs/event-listener-strategy |
| `fastrand` | 1.9.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/fastrand |
| `fastrand` | 2.5.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/fastrand |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | https://github.com/servo/rust-url |
| `fs2` | 0.4.3 | MIT/Apache-2.0 | https://github.com/danburkert/fs2-rs |
| `futures-core` | 0.3.34 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| `futures-io` | 0.3.34 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| `futures-lite` | 1.13.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/futures-lite |
| `futures-lite` | 2.6.1 | Apache-2.0 OR MIT | https://github.com/smol-rs/futures-lite |
| `futures-sink` | 0.3.34 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| `futures-task` | 0.3.34 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| `futures-util` | 0.3.34 | MIT OR Apache-2.0 | https://github.com/rust-lang/futures-rs |
| `generic-array` | 0.14.7 | MIT | https://github.com/fizyk20/generic-array.git |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 | https://github.com/rust-random/getrandom |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | https://github.com/rust-lang/hashbrown |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | https://github.com/KokaKiwi/rust-hex |
| `hkdf` | 0.12.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/KDFs/ |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | https://github.com/RustCrypto/MACs |
| `iana-time-zone` | 0.1.65 | MIT OR Apache-2.0 | https://github.com/strawlab/iana-time-zone |
| `icu_collections` | 2.3.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `icu_locale_core` | 2.3.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `icu_normalizer` | 2.3.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `icu_normalizer_data` | 2.3.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `icu_properties` | 2.3.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `icu_properties_data` | 2.3.0 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `icu_provider` | 2.3.1 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | https://github.com/servo/rust-url/ |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | https://github.com/hsivonen/idna_adapter |
| `indexmap` | 2.14.0 | Apache-2.0 OR MIT | https://github.com/indexmap-rs/indexmap |
| `inout` | 0.1.4 | MIT OR Apache-2.0 | https://github.com/RustCrypto/utils |
| `io-lifetimes` | 1.0.11 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | https://github.com/sunfishcode/io-lifetimes |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 | https://github.com/dtolnay/itoa |
| `keyring` | 2.3.3 | MIT OR Apache-2.0 | https://github.com/hwchen/keyring-rs.git |
| `lazy_static` | 1.5.0 | MIT OR Apache-2.0 | https://github.com/rust-lang-nursery/lazy-static.rs |
| `libc` | 0.2.189 | MIT OR Apache-2.0 | https://github.com/rust-lang/libc |
| `libm` | 0.2.16 | MIT | https://github.com/rust-lang/compiler-builtins |
| `linux-raw-sys` | 0.3.8 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | https://github.com/sunfishcode/linux-raw-sys |
| `litemap` | 0.8.3 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `log` | 0.4.33 | MIT OR Apache-2.0 | https://github.com/rust-lang/log |
| `memchr` | 2.8.3 | Unlicense OR MIT | https://github.com/BurntSushi/memchr |
| `memoffset` | 0.7.1 | MIT | https://github.com/Gilnaa/memoffset |
| `nix` | 0.26.4 | MIT | https://github.com/nix-rust/nix |
| `num` | 0.4.3 | MIT OR Apache-2.0 | https://github.com/rust-num/num |
| `num-bigint` | 0.4.8 | MIT OR Apache-2.0 | https://github.com/rust-num/num-bigint |
| `num-bigint-dig` | 0.8.6 | MIT/Apache-2.0 | https://github.com/dignifiedquire/num-bigint |
| `num-complex` | 0.4.6 | MIT OR Apache-2.0 | https://github.com/rust-num/num-complex |
| `num-integer` | 0.1.47 | MIT OR Apache-2.0 | https://github.com/rust-num/num-integer |
| `num-iter` | 0.1.46 | MIT OR Apache-2.0 | https://github.com/rust-num/num-iter |
| `num-rational` | 0.4.2 | MIT OR Apache-2.0 | https://github.com/rust-num/num-rational |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 | https://github.com/rust-num/num-traits |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | https://github.com/matklad/once_cell |
| `ordered-stream` | 0.2.0 | MIT OR Apache-2.0 | https://github.com/danieldg/ordered-stream |
| `parking` | 2.2.1 | Apache-2.0 OR MIT | https://github.com/smol-rs/parking |
| `pem-rfc7468` | 0.7.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats/tree/master/pem-rfc7468 |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | https://github.com/servo/rust-url/ |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | https://github.com/taiki-e/pin-project-lite |
| `piper` | 0.2.5 | MIT OR Apache-2.0 | https://github.com/smol-rs/piper |
| `pkcs1` | 0.7.5 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats/tree/master/pkcs1 |
| `pkcs8` | 0.10.2 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats/tree/master/pkcs8 |
| `polling` | 2.8.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/polling |
| `potential_utf` | 0.1.6 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 | https://github.com/cryptocorrosion/cryptocorrosion |
| `rand` | 0.8.7 | MIT OR Apache-2.0 | https://github.com/rust-random/rand |
| `rand_chacha` | 0.3.1 | MIT OR Apache-2.0 | https://github.com/rust-random/rand |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 | https://github.com/rust-random/rand |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | https://github.com/briansmith/ring |
| `rsa` | 0.9.10 | MIT OR Apache-2.0 | https://github.com/RustCrypto/RSA |
| `rustix` | 0.37.28 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | https://github.com/bytecodealliance/rustix |
| `rustls` | 0.23.43 | Apache-2.0 OR ISC OR MIT | https://github.com/rustls/rustls |
| `rustls-pki-types` | 1.15.1 | MIT OR Apache-2.0 | https://github.com/rustls/pki-types |
| `rustls-webpki` | 0.103.15 | ISC | https://github.com/rustls/webpki |
| `secret-service` | 3.1.0 | MIT OR Apache-2.0 | https://github.com/hwchen/secret-service-rs.git |
| `security-framework` | 3.7.0 | MIT OR Apache-2.0 | https://github.com/kornelski/rust-security-framework |
| `security-framework-sys` | 2.17.0 | MIT OR Apache-2.0 | https://github.com/kornelski/rust-security-framework |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 | https://github.com/serde-rs/json |
| `sha1` | 0.10.7 | MIT OR Apache-2.0 | https://github.com/RustCrypto/hashes |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | https://github.com/RustCrypto/hashes |
| `signature` | 2.2.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/traits/tree/master/signature |
| `slab` | 0.4.12 | MIT | https://github.com/tokio-rs/slab |
| `smallvec` | 1.15.2 | MIT OR Apache-2.0 | https://github.com/servo/rust-smallvec |
| `socket2` | 0.4.10 | MIT OR Apache-2.0 | https://github.com/rust-lang/socket2 |
| `spin` | 0.9.9 | MIT | https://github.com/mvdnes/spin-rs.git |
| `spki` | 0.7.3 | Apache-2.0 OR MIT | https://github.com/RustCrypto/formats/tree/master/spki |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | https://github.com/storyyeller/stable_deref_trait |
| `static_assertions` | 1.1.0 | MIT OR Apache-2.0 | https://github.com/nvzqz/static-assertions-rs |
| `subtle` | 2.6.1 | BSD-3-Clause | https://github.com/dalek-cryptography/subtle |
| `thiserror` | 2.0.20 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |
| `tinystr` | 0.8.4 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `toml_datetime` | 0.7.5+spec-1.1.0 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| `toml_edit` | 0.23.10+spec-1.0.0 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| `toml_parser` | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| `tracing` | 0.1.44 | MIT | https://github.com/tokio-rs/tracing |
| `tracing-core` | 0.1.36 | MIT | https://github.com/tokio-rs/tracing |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 | https://github.com/paholg/typenum |
| `untrusted` | 0.9.0 | ISC | https://github.com/briansmith/untrusted |
| `ureq` | 2.12.1 | MIT OR Apache-2.0 | https://github.com/algesten/ureq |
| `url` | 2.5.8 | MIT OR Apache-2.0 | https://github.com/servo/rust-url |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | https://github.com/hsivonen/utf8_iter |
| `uuid` | 1.18.1 | Apache-2.0 OR MIT | https://github.com/uuid-rs/uuid |
| `waker-fn` | 1.2.0 | Apache-2.0 OR MIT | https://github.com/smol-rs/waker-fn |
| `webpki-roots` | 0.26.11 | CDLA-Permissive-2.0 | https://github.com/rustls/webpki-roots |
| `webpki-roots` | 1.0.9 | CDLA-Permissive-2.0 | https://github.com/rustls/webpki-roots |
| `winapi` | 0.3.9 | MIT/Apache-2.0 | https://github.com/retep998/winapi-rs |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| `windows-sys` | 0.52.0 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| `windows-targets` | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| `windows_x86_64_msvc` | 0.52.6 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| `winnow` | 0.7.15 | MIT | https://github.com/winnow-rs/winnow |
| `winnow` | 1.0.4 | MIT | https://github.com/winnow-rs/winnow |
| `writeable` | 0.6.4 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `xdg-home` | 1.3.0 | MIT | https://github.com/zeenix/xdg-home |
| `yoke` | 0.8.3 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `zbus` | 3.15.2 | MIT | https://github.com/dbus2/zbus/ |
| `zbus_names` | 2.6.1 | MIT | https://github.com/dbus2/zbus/ |
| `zerocopy` | 0.8.56 | BSD-2-Clause OR Apache-2.0 OR MIT | https://github.com/google/zerocopy |
| `zerofrom` | 0.1.8 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/utils |
| `zerotrie` | 0.2.5 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `zerovec` | 0.11.8 | Unicode-3.0 | https://github.com/unicode-org/icu4x |
| `zmij` | 1.0.23 | MIT | https://github.com/dtolnay/zmij |
| `zvariant` | 3.15.2 | MIT | https://github.com/dbus2/zbus/ |

## npm -- resolved at install time, not vendored

The published `@kleos-research/kaleidoscope` tarball contains only first-party
files (`bin`, `dist/src`, `README.md`, `LICENSE`, `NOTICE`). The packages below are declared dependencies that npm
fetches from the registry into the user's `node_modules`; we redistribute none
of them. They are listed for disclosure.


| Package | Version | Licence |
| --- | --- | --- |
| `@modelcontextprotocol/client` | 2.0.0 | MIT |
| `@modelcontextprotocol/core` | 2.0.0 | MIT |
| `@openai/agents` | 0.17.0 | MIT |
| `@openai/agents-core` | 0.17.0 | MIT |
| `@openai/agents-openai` | 0.17.0 | MIT |
| `@openai/agents-realtime` | 0.17.0 | MIT |
| `@standard-schema/spec` | 1.1.0 | MIT |
| `@types/node` | 26.2.0 | MIT |
| `@types/ws` | 8.18.1 | MIT |
| `cross-spawn` | 7.0.6 | MIT |
| `debug` | 4.4.3 | MIT |
| `eventsource` | 3.0.7 | MIT |
| `eventsource-parser` | 3.1.1 | MIT |
| `isexe` | 2.0.0 | ISC |
| `jose` | 6.2.9 | MIT |
| `ms` | 2.1.3 | MIT |
| `openai` | 7.5.0 | Apache-2.0 |
| `path-key` | 3.1.1 | MIT |
| `pkce-challenge` | 5.0.1 | MIT |
| `shebang-command` | 2.0.0 | MIT |
| `shebang-regex` | 3.0.0 | MIT |
| `undici-types` | 8.3.0 | MIT |
| `which` | 2.0.2 | ISC |
| `ws` | 8.21.3 | MIT |
| `zod` | 4.4.3 | MIT |

## PyPI -- resolved at install time, not vendored

The published `kaleidoscope-memory` wheel contains only `src/kaleidoscope_memory`.
The distributions below are declared dependencies that pip resolves from the
index; we redistribute none of them. Optional extras are marked. Licence strings
are not restated here because pip records the authoritative metadata in the
installed environment and a copy in this file would silently go stale.


| Distribution | Constraint | Role |
| --- | --- | --- |
| `mcp` | `>=1.28.1,<3` | required |
| `claude-agent-sdk` | `==0.2.143` | extra: claude |
| `crewai` | `==1.15.17` | extra: crewai |
| `crewai-tools` | `[mcp]==1.15.17` | extra: crewai |
| `mcp` | `==1.28.1` | extra: crewai |
| `mcp` | `==2.0.0` | extra: generic-mcp-v2 |
| `langchain` | `==1.3.16` | extra: langgraph |
| `langchain-mcp-adapters` | `==0.3.2` | extra: langgraph |
| `langgraph` | `==1.2.11` | extra: langgraph |
| `mcp` | `==1.29.0` | extra: langgraph |
| `openai-agents` | `==0.22.0` | extra: openai |
| `mcp` | `==1.29.0` | extra: openai |
| `pytest` | `==8.4.2` | extra: test |
| `pytest-asyncio` | `==1.2.0` | extra: test |

## How to read a licence expression

The strings above are SPDX expressions copied verbatim from each package's own
metadata. `OR` means the package offers a choice and this project takes it under
whichever term applies; `AND` means every named licence applies at once. Full
licence texts are distributed with each package by its registry.

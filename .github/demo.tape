# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Rendered by `make demo` (vhs, https://github.com/charmbracelet/vhs) from
# the repository root, with CRYPTO_SERVICE_URL and CRYPTO_SERVICE_API_KEY
# naming a crypto-server on loopback (synthetic key). On screen it runs
# examples/hash.rs and examples/ml_kem.rs: a SHA-256 digest, then an
# ML-KEM-768 key held by the server, an encapsulation to its public key
# and a decapsulation by keyId whose shared secrets match. One hidden run
# builds the examples first, so the visible run shows the calls only.
Output .github/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 520
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WaitTimeout 120s
Set WaitPattern /\$\s*$/

Hide
Type `cargo build -q --example hash --example ml_kem && export PS1='$ ' && clear`
Enter
Wait
Show

Type "cargo run -q --example hash"
Sleep 500ms
Enter
Wait
Sleep 2s

Type "cargo run -q --example ml_kem"
Sleep 500ms
Enter
Wait
Sleep 3s

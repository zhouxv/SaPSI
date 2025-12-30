#! /bin/bash
set -e

sed -i '9s/.*/pub const DIMENSION: usize = 2;/' ./sa/src/config.rs
cargo build --release
cp ./target/release/psi ./psi_dim2

sed -i '9s/.*/pub const DIMENSION: usize = 4;/' ./sa/src/config.rs
cargo build --release
cp ./target/release/psi ./psi_dim4

sed -i '9s/.*/pub const DIMENSION: usize = 6;/' ./sa/src/config.rs
cargo build --release
cp ./target/release/psi ./psi_dim6

sed -i '9s/.*/pub const DIMENSION: usize = 10;/' ./sa/src/config.rs
cargo build --release
cp ./target/release/psi ./psi_dim10

sed -i '9s/.*/pub const DIMENSION: usize = 15;/' ./sa/src/config.rs
cargo build --release
cp ./target/release/psi ./psi_dim15
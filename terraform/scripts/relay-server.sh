#!/bin/bash
yum update -y
yum install -y curl
yum install -y gcc
sudo -u ec2-user -i <<'EOF'
ROOT=$(pwd)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
cargo install mpc-relay
mpc-relay generate-keypair -f server.pem
echo 'key = "server.pem"' > config.toml
sudo mpc-relay start config.toml --bind 0.0.0.0:80
EOF

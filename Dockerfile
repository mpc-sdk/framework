FROM rust:1.75-buster AS rust

WORKDIR /usr/app

COPY bindings bindings
COPY client client
COPY driver driver
COPY protocol protocol
COPY server server
COPY src src
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY config.toml config.toml
RUN cargo build --release --bin mpc-relay

CMD /usr/app/target/release/mpc-relay start --bind 0.0.0.0:8080 /usr/app/config.toml

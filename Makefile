.PHONY: dev release universal test lint fmt check install run
dev:        ; cargo build
release:    ; cargo build --release
universal:  ; scripts/build-universal.sh
test:       ; cargo test
fmt:        ; cargo fmt
lint:       ; cargo fmt --check && cargo clippy --all-targets -- -D warnings
check: lint test release
install: release ; scripts/install.sh target/release/sshweb
run:        ; cargo run -- serve

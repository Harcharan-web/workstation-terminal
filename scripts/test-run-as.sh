#!/usr/bin/env bash
# Run tests/run_as.rs for real: a Linux container with the gateway's account (svc), the shells'
# account (work), an account sudo refuses (other) and packaging/sshweb.sudoers installed for them.
# Needs Docker. Usage: scripts/test-run-as.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD:/src:ro" -v sshweb-run-as-target:/target -v sshweb-run-as-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target rust:1-slim-bookworm bash -euc '
    apt-get update -qq >/dev/null && apt-get install -y -qq sudo procps >/dev/null 2>&1
    useradd -m -s /bin/bash svc; useradd -m -s /bin/bash work; useradd -m -s /bin/bash other
    chmod 750 /home/work; setfacl -m u:svc:x /home/work 2>/dev/null || chmod o+x /home/work
    sed -e "s/_sshweb/svc/g; s/(workstation)/(work)/" /src/packaging/sshweb.sudoers > /etc/sudoers.d/sshweb
    chmod 440 /etc/sudoers.d/sshweb && visudo -cf /etc/sudoers.d/sshweb
    cp -r /src /build && cd /build
    bin=$(cargo test --quiet --test run_as --no-run --message-format=json 2>/dev/null \
      | grep -o "\"executable\":\"[^\"]*run_as[^\"]*\"" | cut -d\" -f4)
    chmod -R o+rX /target
    su svc -s /bin/bash -c "SSHWEB_TEST_RUN_AS=work SSHWEB_TEST_RUN_AS_REFUSED=other $bin --nocapture --test-threads=1"
  '

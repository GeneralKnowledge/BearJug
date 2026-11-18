#!/usr/bin/env bash
# CI only: build the world around a sensor on one fresh Ubuntu 24.04 machine.
#
#   * a collector container on its own Docker network (172.31.200.10), with
#     the sensor registered and a certificate for collector.bearjug.internal;
#   * deploy/ansible/secrets-ci/ with the sensor key and collector certificate,
#     as collector.yml would leave them on the Ansible controller;
#   * an "external machine": network namespace bj-ext (10.250.0.2) routed to
#     the host (10.250.0.1) through a veth pair, so its traffic reaches the
#     sensor the way an attacker's does (prerouting, DNAT, forward).
#
# Usage: sudo deploy/ci/prepare.sh SENSOR_ID
set -euo pipefail
SENSOR_ID=${1:?sensor id}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SECRETS=$ROOT/deploy/ansible/secrets-ci
COLL_NET=bj-test-collector
COLL_IP=172.31.200.10

docker build -q -t bearjug/collector-ci -f "$ROOT/deploy/ci/collector.Dockerfile" "$ROOT"
docker network inspect $COLL_NET >/dev/null 2>&1 || \
  docker network create --subnet 172.31.200.0/24 -o com.docker.network.bridge.name=bj-test-coll $COLL_NET

mkdir -p "$SECRETS/sensors"
chmod 700 "$SECRETS"
docker volume create bj-collector-data >/dev/null
docker run --rm -v bj-collector-data:/data -v "$SECRETS:/out" bearjug/collector-ci sh -ec "
  bearjug-collector --data /data/store init
  bearjug-collector --data /data/store add-sensor $SENSOR_ID --key-out /out/sensors/$SENSOR_ID.key
  python3 - <<'PY'
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'collector.bearjug.internal')])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('collector.bearjug.internal')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256()))
open('/data/tls.key', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open('/data/tls.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
open('/out/collector-ca.pem', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
PY
"
docker rm -f bj-collector >/dev/null 2>&1 || true
docker run -d --restart unless-stopped --name bj-collector --network $COLL_NET --ip $COLL_IP -v bj-collector-data:/data \
  bearjug/collector-ci bearjug-collector --data /data/store serve --host 0.0.0.0 --port 8443 \
  --tls-cert /data/tls.crt --tls-key /data/tls.key >/dev/null
chown -R "${SUDO_USER:-root}" "$SECRETS"

# The external machine.
if ! ip netns list | grep -qw bj-ext; then
  ip netns add bj-ext
  ip link add bj-ext-host type veth peer name bj-ext-ns
  ip link set bj-ext-ns netns bj-ext
  ip addr add 10.250.0.1/30 dev bj-ext-host
  ip link set bj-ext-host up
  ip netns exec bj-ext ip addr add 10.250.0.2/30 dev bj-ext-ns
  ip netns exec bj-ext ip link set bj-ext-ns up
  ip netns exec bj-ext ip link set lo up
  ip netns exec bj-ext ip route add default via 10.250.0.1
fi
sysctl -q -w net.ipv4.ip_forward=1
echo "prepared: collector at $COLL_IP, external machine 10.250.0.2 -> sensor 10.250.0.1"

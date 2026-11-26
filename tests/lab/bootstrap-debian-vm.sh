#!/usr/bin/env bash
# Build a clean Debian root filesystem and boot it with its own kernel and systemd.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted

scratch=$(mktemp -d)
container=
vm_pid=
image="vpn-orbit-debian-vm:${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
port=2229
cleanup() {
    status=$?
    if [[ -n "$vm_pid" ]]; then
        if (( status )); then
            tail -n 100 "$scratch/serial.log" || true
        fi
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    if [[ -n "$container" ]]; then
        docker rm -f "$container" >/dev/null || true
    fi
    docker image rm "$image" >/dev/null 2>&1 || true
    sudo rm -rf -- "$scratch"
}
trap cleanup EXIT

docker build --platform linux/amd64 -t "$image" - < tests/lab/Dockerfile.bootstrap-debian
container=$(docker create "$image")
root="$scratch/root"
mkdir "$root"
docker export "$container" | sudo tar --numeric-owner -xf - -C "$root"

# Provision a one-use SSH identity and a pinned host key before the VM boots.
ssh-keygen -q -t ed25519 -N '' -f "$scratch/id"
ssh-keygen -q -t ed25519 -N '' -f "$scratch/host"
sudo install -m 0600 "$scratch/host" "$root/etc/ssh/ssh_host_ed25519_key"
sudo install -m 0644 "$scratch/host.pub" "$root/etc/ssh/ssh_host_ed25519_key.pub"
sudo install -d -m 0700 "$root/root/.ssh"
sudo install -m 0600 "$scratch/id.pub" "$root/root/.ssh/authorized_keys"
printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' |
    sudo tee "$root/etc/ssh/sshd_config.d/00-ci.conf" >/dev/null
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$scratch/host.pub")" > "$scratch/known_hosts"

# QEMU supplies IPv4 DHCP and a DNS forwarder on the guest-private network.
sudo install -d "$root/etc/systemd/network"
printf '[Match]\nDriver=virtio_net\n[Network]\nDHCP=ipv4\n' |
    sudo tee "$root/etc/systemd/network/10-ci.network" >/dev/null
sudo rm -f "$root/etc/resolv.conf"
printf 'nameserver 10.0.2.3\n' | sudo tee "$root/etc/resolv.conf" >/dev/null
sudo truncate -s 0 "$root/etc/machine-id"

kernel=("$root"/boot/vmlinuz-*)
initrd=("$root"/boot/initrd.img-*)
test "${#kernel[@]}" = 1 && test "${#initrd[@]}" = 1
sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 "${kernel[0]}" "$scratch/kernel"
sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 "${initrd[0]}" "$scratch/initrd"
truncate -s 12G "$scratch/disk.img"
sudo mkfs.ext4 -q -F -d "$root" "$scratch/disk.img"

acceleration=(-accel tcg,thread=multi -cpu max)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    acceleration=(-accel kvm -cpu host)
fi
printf "QEMU acceleration: %s\n" "${acceleration[1]}"
qemu-system-x86_64 "${acceleration[@]}" -m 4096 -smp 4 -display none -monitor none \
    -serial "file:$scratch/serial.log" -kernel "$scratch/kernel" -initrd "$scratch/initrd" \
    -append 'root=/dev/vda rw console=ttyS0' \
    -drive "file=$scratch/disk.img,format=raw,if=virtio" \
    -netdev "user,id=network,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=network &
vm_pid=$!

options=(-F /dev/null -o BatchMode=yes -o ConnectTimeout=4 -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$scratch/known_hosts"
    -o GlobalKnownHostsFile=/dev/null -i "$scratch/id")
guest=root@127.0.0.1
ssh_vm() { ssh "${options[@]}" -p "$port" "$guest" "$@"; }

timeout=240
deadline=$(( SECONDS + timeout ))
until ssh_vm 'systemctl is-active --quiet systemd-networkd.service' 2>/dev/null; do
    kill -0 "$vm_pid"
    if (( SECONDS >= deadline )); then
        ssh_vm 'systemctl is-active systemd-networkd.service' || true
        printf 'Timed out waiting for the Debian VM SSH connection.\n' >&2
        exit 1
    fi
    sleep 2
done
printf 'Debian VM is reachable over the pinned SSH connection.\n'

git bundle create "$scratch/source.bundle" HEAD
scp "${options[@]}" -P "$port" "$scratch/source.bundle" "$guest:/root/source.bundle"
ssh_vm bash -s -- "$(git rev-parse HEAD)" <<'GUEST'
set -euo pipefail
test "$(dpkg --print-architecture)" = amd64
. /etc/os-release
test "$ID:$VERSION_ID:$VERSION_CODENAME" = debian:13:trixie
test ! -e /usr/bin/docker
test ! -S /run/dbus/system_bus_socket
mkdir -m 0700 /root/source
cd /root/source
git init -q
git fetch -q /root/source.bundle HEAD
git checkout -q --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "$1"
trap 'journalctl --no-pager -n 60 -u vpn-orbit-compose -u vpn-orbit-web -u vpn-orbit-broker -u vpn-orbit-supervisor -u vpn-orbit-vault-initialize -u dbus' ERR
./install
RUNNER_ENVIRONMENT=github-hosted python3 tests/lab/bootstrap_install.py
GUEST

boot_id=$(ssh_vm 'cat /proc/sys/kernel/random/boot_id')
ssh_vm 'systemd-run --on-active=2s systemctl reboot'
deadline=$(( SECONDS + timeout ))
until next_boot=$(ssh_vm 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null) && [[ "$next_boot" != "$boot_id" ]]; do
    kill -0 "$vm_pid"
    (( SECONDS < deadline ))
    sleep 2
done
ssh_vm 'curl --disable --fail --silent --show-error --noproxy "*" --retry 12 --retry-connrefused --retry-max-time 90 --max-time 5 --cacert /opt/vpn-orbit-bootstrap/web-ca.pem https://127.0.0.1:18443/healthz'

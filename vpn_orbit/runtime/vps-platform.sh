. /etc/os-release
orbit_arch=$(dpkg --print-architecture 2>/dev/null || printf unknown)
case "${ID:-}:${VERSION_ID:-}:$orbit_arch" in
    ubuntu:24.04:amd64) orbit_platform=UBUNTU_24_04 ;;
    ubuntu:26.04:amd64) orbit_platform=UBUNTU_26_04 ;;
    debian:13:amd64) orbit_platform=DEBIAN_13 ;;
    *) orbit_platform=UNSUPPORTED ;;
esac

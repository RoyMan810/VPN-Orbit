# Read-only checks inside the authenticated SSH session.
orbit_default_route() {
    if [ -x /usr/sbin/ip ]; then
        orbit_ip=/usr/sbin/ip
    elif [ -x /usr/bin/ip ]; then
        orbit_ip=/usr/bin/ip
    else
        printf UNKNOWN
        return
    fi
    if ! orbit_routes=$(/usr/bin/timeout --kill-after=1s 1s "$orbit_ip" "$1" route show table main default 2>/dev/null); then
        printf UNKNOWN
    elif printf '%s\n' "$orbit_routes" | /usr/bin/grep -q '^default[[:space:]]'; then
        printf PRESENT
    else
        printf ABSENT
    fi
}

orbit_executable() {
    for orbit_path do
        if [ -f "$orbit_path" ] && [ -x "$orbit_path" ]; then
            printf PRESENT
            return
        fi
    done
    printf NOT_DETECTED
}

orbit_ipv4=$(orbit_default_route -4)
orbit_ipv6=$(orbit_default_route -6)
orbit_docker=$(orbit_executable /usr/bin/docker /usr/local/bin/docker)
orbit_compose=$(orbit_executable /usr/local/lib/docker/cli-plugins/docker-compose \
    /usr/local/libexec/docker/cli-plugins/docker-compose /usr/lib/docker/cli-plugins/docker-compose \
    /usr/libexec/docker/cli-plugins/docker-compose)

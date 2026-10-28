# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.22-alpine AS build
WORKDIR /src

# Cache deps first. go.sum may not exist yet (stdlib-only); the glob tolerates that.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/veild ./cmd/veild

# ---- runtime stage ----
# Alpine, not distroless: the honeypot shells out to `iptables` (host-side nat
# REDIRECT), and distroless ships none. Same digest-pinned alpine:3.20 the box
# runs, so a host that already pulled it pays nothing extra.
#
# IPTABLES_BACKEND must match the host's: veild edits the host's netfilter (the
# compose service runs on the host network), and rules written through the
# other backend still filter traffic but sit in tables the host's `iptables`
# and Docker don't see. nft is the default on current distros (Ubuntu 21.10+,
# Debian 11+); check with `iptables --version` on the host — "(legacy)" means
# build with --build-arg IPTABLES_BACKEND=legacy (and add
# deploy/docker-compose.legacy.yml, which shares the host's xtables lock).
#
# Userspace skew: alpine 3.20 ships iptables 1.8.10. On nft, an older host
# binary (e.g. Ubuntu 22.04's 1.8.7) may not decode rules 1.8.10 wrote and list
# them as incompatible; the rules still work, so inspect them with this image's
# binary (`docker compose exec veild iptables -t nat -S`). Legacy has no skew.
#
# Kernel modules: the container has no CAP_SYS_MODULE, so the nat/REDIRECT
# modules must already be loaded on the host (see the README's Docker Compose
# section for the modprobe line).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
ARG IPTABLES_BACKEND=nft
# Alpine 3.20 is not /usr-merged: iptables lives in /sbin, so paths are
# resolved with `command -v` rather than hard-coded. The final check asserts
# the selected backend, not merely that some iptables runs.
RUN case "$IPTABLES_BACKEND" in \
      nft) apk add --no-cache iptables ;; \
      legacy) apk add --no-cache iptables iptables-legacy \
        && ln -sf "$(command -v iptables-legacy)" "$(command -v iptables)" ;; \
      *) echo "IPTABLES_BACKEND must be nft or legacy, got: $IPTABLES_BACKEND" >&2; exit 1 ;; \
    esac \
 && want="$( [ "$IPTABLES_BACKEND" = nft ] && echo nf_tables || echo legacy )" \
 && iptables --version \
 && iptables --version | grep -q "($want)" \
 || { echo "iptables is not the $IPTABLES_BACKEND backend" >&2; exit 1; }
WORKDIR /app
COPY --from=build /out/veild /app/veild
# The dashboard's FileServer serves ./web relative to the working directory.
COPY web /app/web
# Root, deliberately: veild needs NET_ADMIN (honeypot iptables), NET_RAW
# (AF_PACKET tap) and NET_BIND_SERVICE (resolver on gateway:53), and its
# iptables child needs them too. A non-root process gets none of the container's
# capabilities without file caps on both binaries plus ambient caps, and the
# docker.sock it drives is root-equivalent anyway, so a non-root UID would buy no
# containment. The compose file drops every other capability.
USER root
ENTRYPOINT ["/app/veild"]

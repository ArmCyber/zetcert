# The server under test: Debian 13 with nginx, certbot 4.0, Node 20 and npm from apt.
FROM debian:trixie
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nginx certbot nodejs npm openssl ca-certificates curl procps iproute2 sudo \
 && rm -rf /var/lib/apt/lists/*
# certbot talks to Pebble instead of Let's Encrypt.
RUN mkdir -p /etc/letsencrypt && printf 'server = https://pebble:14000/dir\n' > /etc/letsencrypt/cli.ini
# A normal user with sudo, to run the first `zetcert init` the way users do.
RUN useradd -m tester && echo 'tester ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/tester
CMD ["sleep", "infinity"]

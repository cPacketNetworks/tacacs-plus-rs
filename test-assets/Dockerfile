FROM debian:12-slim AS shrubbery-base

# build dependencies for tac_plus
# we have to build from source since the tacacs+ package was removed from repos after Debian Buster
RUN apt-get update && apt-get install -y gcc make flex bison libwrap0-dev && rm -rf /var/lib/apt/lists/*

# extract source archive downloaded from shrubbery website: https://shrubbery.net/pub/tac_plus/
ADD tacacs-F4.0.4.28.tar.gz /opt/

WORKDIR /opt/tacacs-F4.0.4.28
RUN ./configure && make && make install

# update ld cache to pick up on libtacacs
RUN ldconfig

# run TACACS+ daemon listening on port 5555
# -G => run in foreground
ENTRYPOINT ["tac_plus", "-p", "5555", "-G"]

EXPOSE 5555

FROM shrubbery-base AS shrubbery-configured

# basic TACACS+ daemon configuration
COPY <<EOF /srv/tac_plus/tac_plus.conf
key = "very secure key that is super secret"
accounting file = /tmp/accounting.log

user = someuser {
    pap = cleartext hunter2
    chap = cleartext "something different"

    service = authorizeme {
        number = 42
        optional thing = "not important"
    }
}

user = paponly {
    pap = cleartext pass-word
}

user = DEFAULT {
    service = guest {
        priv-lvl = 0
        authenticated = false
    }
}
EOF

# potential flags of interest:
# -S => allow for clients to negotiate single connection mode
# -g => single-threaded (logs print to stderr; ignores -S flag)
# -d => specify debug level (as bitflag values ORed together)
CMD ["-C", "/srv/tac_plus/tac_plus.conf", "-S"]


FROM debian:12-slim AS ng-base

RUN --mount=type=cache,target=/var/cache/apt,id=ng-apt \
    apt-get update && apt-get install -y \
    # tools
    git gcc make \
    # library dependencies
    libc-dev libssl-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/MarcJHuber/event-driven-servers.git /opt/event-driven-servers

WORKDIR /opt/event-driven-servers
RUN ./configure
RUN make && make install

ENTRYPOINT ["tac_plus-ng"]

FROM ng-base AS ng-configured

# single quotes around EOF prevent parameter expansion (${VARIABLE}) which we need for the accounting format to work properly
# see https://www.gnu.org/software/bash/manual/bash.html#Here-Documents for more info
COPY <<'EOF' /srv/tac_plus-ng/tacacs.conf
id = spawnd {
    listen { port = 5555 }
}

id = tac_plus-ng {
    log acctlog {
        destination = /tmp/accounting.log
        # match shrubbery format
        # service is included separately from args since args omits it for some reason
        accounting format = "%b %d %H:%M:%S\t${device.address}\t${user}\t${device.port}\t${client}\t${accttype}\t${args,\t}\n"
    }
    accounting log = acctlog

    profile authorizeme {
        script {
            set number = 42
            optional thing = "not important"
            permit
        }
    }

    profile guest {
        script {
            set priv-lvl = 0
            set authenticated = false
            permit
        }
    }

    # to allow empty username guest authorization to work
    rewrite emptyGuest {
        rewrite /^$/ guest
    }

    device everything {
        key = "very secure key that is super secret"
        address = 0.0.0.0/0

        script { rewrite user = emptyGuest }
    }

    user guest {
        rewritten-only
    }

    user someuser {
        password pap = clear hunter2
        password chap = clear "something different"
    }

    user paponly {
        password pap = clear pass-word
    }

    ruleset {
        rule profile-assignment {
            enabled = yes
            script {
                if (service == guest) {
                    profile = guest
                }

                if (service == authorizeme) {
                    profile = authorizeme
                }

                permit
            }
        }
    }
}
EOF

# validate config
RUN tac_plus-ng -P /srv/tac_plus-ng/tacacs.conf

CMD ["/srv/tac_plus-ng/tacacs.conf"]

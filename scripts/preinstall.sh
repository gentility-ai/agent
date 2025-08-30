#!/bin/sh
# Fix locale to avoid perl warnings
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

# Create gentility user and group if they don't exist
if ! getent group gentility >/dev/null 2>&1; then
    groupadd --system gentility
fi
if ! getent passwd gentility >/dev/null 2>&1; then
    useradd --system --gid gentility --no-create-home \
            --home-dir /var/lib/gentility-agent \
            --shell /usr/sbin/nologin \
            --comment "Gentility AI Agent" gentility
fi
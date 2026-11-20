# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Container image for the Gentility agent, for hosts where a package install
# does not fit (Kubernetes, ECS, Compose).
#
# Runs as an unprivileged user, needs no writable root filesystem and no
# inbound port: it only dials out to wss://ws.gentility.ai on 443 and to the
# databases it is asked to query.
#
# It starts in database-only mode (GENTILITY_MODE=database): SQL queries only,
# no shell, file or egress commands. Set GENTILITY_MODE=full to lift that.
#
#   docker run --read-only -e GENTILITY_TOKEN=genkey-agent-... ghcr.io/gentility-ai/agent

# Base images are pinned by digest; bump the tag and the digest together.
FROM crystallang/crystal:1.22.2-alpine@sha256:a0c2fb92a6ce855e8d40bdffe729e2fcccf98dac929d0f9f589fad8c88e297a1 AS build
WORKDIR /src
COPY shard.yml shard.lock ./
RUN shards install --production
COPY src ./src
COPY VERSION ./
RUN mkdir /out && crystal build src/agent.cr --release --static --no-debug -o /out/gentility

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
# psql and mysql are what the agent runs queries with.
RUN apk add --no-cache ca-certificates postgresql17-client mariadb-client \
 && addgroup -S -g 10001 gentility \
 && adduser -S -u 10001 -G gentility -h /var/lib/gentility gentility
COPY --from=build /out/gentility /usr/local/bin/gentility

# Optional state (stored database credentials, the key-exchange seed). Mount a
# volume here to keep it; without one the agent runs stateless.
ENV GENTILITY_CONFIG=/var/lib/gentility/gentility.yaml \
    GENTILITY_MODE=database
USER 10001:10001
WORKDIR /var/lib/gentility
ENTRYPOINT ["/usr/local/bin/gentility"]
CMD ["run"]

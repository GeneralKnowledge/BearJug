# BearJug Cowrie image: a pinned Cowrie release plus the BearJug overlay.
#
#   docker build -t bearjug/cowrie:3.1.7-bj1 deploy/cowrie
#
# Everything is pinned: the Cowrie commit (checked after fetching), every base
# image by digest, and Cowrie's Python requirements (its requirements.txt pins
# exact versions, and only prebuilt wheels are accepted, so no compiler is
# needed or present). Bumping any of them is a reviewed change, and the overlay
# refuses to apply if a file it replaces has changed upstream.

ARG COWRIE_COMMIT=8e36327f6a24abe379dac807cc7e8b2d2fb01248

# --- 1. Cowrie source at the pinned commit, with the overlay applied --------
FROM alpine/git@sha256:2306e2b05ee0ef99f5d25b0779f645b24ae9f91ba187107503592fcdfe78da3a AS source
ARG COWRIE_COMMIT
RUN git init -q /cowrie/cowrie-git && cd /cowrie/cowrie-git && \
    git remote add origin https://github.com/cowrie/cowrie.git && \
    git fetch -q --depth 1 origin "${COWRIE_COMMIT}" && \
    git checkout -q FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "${COWRIE_COMMIT}" && \
    rm -rf .git

# --- 2. Overlay and Python dependencies ---------------------------------------
# Same CPython minor version (3.13) as the distroless runtime below.
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS builder
COPY --from=source /cowrie/cowrie-git /cowrie/cowrie-git
COPY overlay /build/overlay
RUN python3 /build/overlay/apply.py /cowrie/cowrie-git
RUN pip install -q --no-cache-dir --disable-pip-version-check --only-binary=:all: \
      --target /cowrie/lib -r /cowrie/cowrie-git/requirements.txt
COPY entrypoint.py /cowrie/bearjug_entrypoint.py
# Only what Cowrie needs at runtime: no tests, docs, helper scripts, proxy pool
# configs or the permissive example user database.
RUN cd /cowrie/cowrie-git && \
    rm -rf docs docker bin etc var src/cowrie/test src/cowrie/data/pool_configs \
           src/cowrie/data/etc/userdb.example && \
    mkdir etc && \
    find /cowrie -name '__pycache__' -prune -exec rm -rf {} +

# --- 3. Runtime: distroless, so no shell, package manager or setuid binaries --
FROM gcr.io/distroless/python3-debian13@sha256:60faad2efce94a847f32e2adbcaefeb2e4fd3e3a78075a3abb600904a5e010e9
ARG COWRIE_COMMIT
LABEL org.opencontainers.image.title="BearJug Cowrie sensor" \
      org.opencontainers.image.source="https://github.com/GeneralKnowledge/BearJug" \
      org.opencontainers.image.licenses="BSD-3-Clause AND Apache-2.0" \
      io.bearjug.cowrie.commit="${COWRIE_COMMIT}"
COPY --from=builder --chown=0:0 /cowrie /cowrie
ENV PYTHONPATH=/cowrie/lib:/cowrie/cowrie-git/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC
# Byte-compile and build Twisted's plugin cache now: the root filesystem is
# read-only at runtime.
RUN ["python3", "-c", "import compileall, sys; sys.exit(0 if compileall.compile_dir('/cowrie', quiet=1) else 1)"]
RUN ["python3", "-c", "from twisted.plugin import IPlugin, getPlugins; import twisted.plugins; assert any(p.tapname == 'cowrie' for p in getPlugins(IPlugin) if hasattr(p, 'tapname'))"]
# Overridden at run time with the host's bearjug-cowrie uid and spool gid.
USER 65532:65532
WORKDIR /cowrie/cowrie-git
EXPOSE 2222
STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/cowrie/bearjug_entrypoint.py"]

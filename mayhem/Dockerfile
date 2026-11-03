# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form, PREFERRED) — builds ON TOP of the org C/C++ base
# image (ghcr.io/savantenvs/base). The base already provides debian + clang/llvm +
# libFuzzer/afl++ + the identities + the build-contract ENV, so this only adds the
# per-commit build (built on top of the prebuilt base, rather than building the toolchain in-image).
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

# The org base, pinned to a fixed DATE-tagged base (YYYYMMDD; shared by all integrations
# minted against it). Use the current dated tag; pin by digest in production: ...base@sha256:<digest>.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); do NOT bake it as an ENV — an
# empty value breaks clang ("must be a non-negative decimal integer") both here and for
# any in-image rebuild. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# To change it for a build (e.g. ASan-only, or add MSan): --build-arg SANITIZER_FLAGS="...".
# Declare it WITHOUT a default (no '='): an undefaulted ARG lets the base ENV flow through to
# build.sh when not passed, and an explicit --build-arg overrides it. (An empty default — `=` —
# would instead shadow the base ENV and silently wipe the sanitizers.)
ARG SANITIZER_FLAGS
# Coverage (optional, off by default): instrument the TEST build to measure how much of the project
# the suite exercises — --build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping".
# Empty by default (no effect on the normal oracle build); build.sh appends it to the test build only.
ARG COVERAGE_FLAGS=
# Build parallelism (optional). build.sh falls back to nproc when unset: --build-arg MAYHEM_JOBS=8
ARG MAYHEM_JOBS=

# If mayhem/build.sh needs EXTRA apt packages, install them as root before the build
# (re-pin to SOURCE_DATE_EPOCH first for reproducibility — repro-sources-list.sh ships
# in the base):
#   USER root
#   RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
#       apt-get update && apt-get install -yq --no-install-recommends <pkgs> \
#    && rm -rf /var/lib/apt/lists/*
#   USER mayhem

USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        libgmp-dev libssl-dev libboost-dev libboost-system-dev libboost-thread-dev \
        libboost-filesystem-dev libboost-program-options-dev libboost-chrono-dev libboost-test-dev \
        libdb5.3++-dev libevent-dev zlib1g-dev make autoconf automake cmake curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Dependencies of the node sources behind the spark_spend_parser target (spark/state.cpp links the node's
# validation layer). They are the same pinned tarballs firo's own `depends/` fetches (versions and sha256 are
# copied from depends/packages/{bls-dash,tor,immer}.mk); they are built here, at image build, into /opt/firo-deps
# so that mayhem/build.sh itself stays offline and re-runnable. Built without sanitizers: they are not fuzzed.
COPY depends/patches/bls-dash/bls-signatures.patch depends/patches/tor/configure.patch /tmp/firo-patches/
COPY depends/config.guess depends/config.sub /tmp/firo-patches/
RUN set -eux; mkdir -p /opt/firo-deps /tmp/firo-deps-src; cd /tmp/firo-deps-src; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch bls.tgz https://github.com/dashpay/bls-signatures/archive/1.1.0.tar.gz 276c8573104e5f18bb5b9fd3ffd49585dda5ba5f6de2de74759dda8ca5a9deac; \
    fetch relic-toolkit-3a23142be0a5510a3aa93cd6c76fc59d3fc732a5.tar.gz https://github.com/relic-toolkit/relic/archive/3a23142be0a5510a3aa93cd6c76fc59d3fc732a5.tar.gz ddad83b1406985a1e4703bd03bdbab89453aa700c0c99567cf8de51c205e5dde; \
    fetch immer.tgz https://github.com/arximboldi/immer/archive/refs/tags/v0.9.1.tar.gz b18b92ba60ec3186dc36ef671d3c2ae542cbb63eb6dc0e258476c6111a67c971; \
    fetch tor.tgz https://archive.torproject.org/tor-package-archive/tor-0.4.9.15.tar.gz 1911f5b216a6814ed143a08bbcff1c6dc96d2ca3b505df9a21876080a92963f3; \
    mkdir bls && tar --strip-components=1 -xf bls.tgz -C bls && cd bls; \
    patch -p1 < /tmp/firo-patches/bls-signatures.patch; \
    cp ../relic-toolkit-3a23142be0a5510a3aa93cd6c76fc59d3fc732a5.tar.gz .; \
    sed -i 's|GIT_REPOSITORY https://github.com/relic-toolkit/relic.git|URL "../../relic-toolkit-3a23142be0a5510a3aa93cd6c76fc59d3fc732a5.tar.gz"|' src/CMakeLists.txt; \
    sed -i 's|GIT_TAG        .*RELIC_GIT_TAG.*|URL_HASH SHA256=ddad83b1406985a1e4703bd03bdbab89453aa700c0c99567cf8de51c205e5dde|' src/CMakeLists.txt; \
    mkdir build && cd build; \
    CC=clang CXX=clang++ cmake .. -DCMAKE_INSTALL_PREFIX=/opt/firo-deps -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        -DSTLIB=ON -DSHLIB=OFF -DSTBIN=ON -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 \
        -DOPSYS=LINUX -DCMAKE_SYSTEM_NAME=Linux -DWSIZE=64 -DCMAKE_C_FLAGS=-UBLSALLOC_SODIUM -DCMAKE_CXX_FLAGS=-UBLSALLOC_SODIUM; \
    make -j"$(nproc)"; make install; cd /tmp/firo-deps-src; \
    mkdir immer && tar --strip-components=1 -xf immer.tgz -C immer && cp -r immer/immer /opt/firo-deps/include/; \
    mkdir tor && tar --strip-components=1 -xf tor.tgz -C tor && cd tor; \
    cp -f /tmp/firo-patches/config.guess /tmp/firo-patches/config.sub .; patch -p1 < /tmp/firo-patches/configure.patch; \
    ./configure --with-pic --disable-system-torrc --disable-systemd --disable-lzma --disable-asciidoc --disable-libscrypt \
        --disable-gcc-hardening --enable-pic --disable-unittests --disable-tool-name-check --disable-seccomp \
        ac_cv_header_sys_capability_h=no ac_cv_lib_cap_cap_init=no ac_cv_func_cap_set_proc=no \
        CC=clang CFLAGS="-std=gnu11 -fPIC" --disable-dependency-tracking; \
    make -j"$(nproc)" libtor.a; install -m 644 libtor.a /opt/firo-deps/lib/; \
    rm -rf /tmp/firo-deps-src /tmp/firo-patches
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git
# history) is copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Anything a Dockerfile step materializes into the tree (downloaded fixtures, generated headers,
# vendored deps) MUST be committed or (re)created by build.sh: rlenv's patch grader runs
# `git clean -ffdX` before every graded build, so a gitignored, untracked file is gone by then and
# every honest patch scores zero (SPEC §6.2 item 16; verify-repo.sh checks it).
#
# OPTIONAL compile-cache pre-fill (SPEC §6.2 item 18). Bases minted with /opt/mayhem/ccache/prefill
# run the build under rlenv's pinned ccache, so the patch grader's first (otherwise cold) rebuild is
# warm — this is what keeps large C/C++ targets inside the build time limit. Older bases fall back to
# the plain build; a missing or stale pre-fill only costs a cold cache. Never enable ccache in
# build.sh or via ENV/PATH, and keep the compiler resolving by name (CC=clang) or nothing is cached.
RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

# Run the project's functional tests at build time IF the repo ships them (mayhem/test.sh is
# optional — omit it only when the repo has no tests meaningful for RL). A failing suite fails the
# image build, so the commit image is guaranteed to build AND pass its own tests.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem

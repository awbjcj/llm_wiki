# syntax=docker/dockerfile:1.7
#
# LLM Wiki served in the browser.
#
# LLM Wiki is a Tauri desktop app (React UI + ~35k lines of Rust backend over
# Tauri IPC), so it cannot run as a plain static web site. This image builds
# the native Linux .deb exactly like the upstream ubuntu-22.04 CI job, then
# runs it inside jlesage/baseimage-gui, which streams the app window to the
# browser over noVNC (HTTP + WebSocket on WEB_LISTENING_PORT).

ARG UBUNTU_VERSION=22.04
ARG NODE_VERSION=22

# ── Stage 1: build the Tauri .deb ────────────────────────────────────────────
FROM node:${NODE_VERSION}-bookworm-slim AS node
FROM ubuntu:${UBUNTU_VERSION} AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl file git pkg-config libssl-dev \
        libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf \
        protobuf-compiler libprotobuf-dev xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Node (official binaries target glibc 2.28, so they run on 22.04).
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Rust (Cargo.toml declares rust-version = 1.88).
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable

WORKDIR /src

# Dependency layers first so source edits do not reinstall node_modules.
COPY package.json package-lock.json ./
COPY mcp-server/package.json mcp-server/package-lock.json ./mcp-server/
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund && npm --prefix mcp-server ci --no-audit --no-fund

COPY index.html components.json tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts ./
COPY src ./src
COPY src-tauri ./src-tauri
COPY mcp-server ./mcp-server
RUN sha256sum -c src-tauri/pdfium/SHA256SUMS --ignore-missing

# The desktop release profile (fat LTO, 1 codegen unit) links slowly on a
# single core. For the image, thin LTO across 16 units compiles several times
# faster for a slightly larger binary. Pass --build-arg
# CARGO_PROFILE_RELEASE_LTO=true --build-arg CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
# to get the exact desktop release build. Cargo reads these as env vars.
ARG CARGO_PROFILE_RELEASE_LTO=thin
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16

# tauri build runs beforeBuildCommand (npm run build:desktop): MCP server +
# typecheck + vite build, then compiles the Rust app and bundles the .deb.
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/src-tauri/target \
    npx tauri build --bundles deb \
    && mkdir -p /out \
    && cp src-tauri/target/release/bundle/deb/*.deb /out/llm-wiki.deb

# ── Stage 2: browser-accessible runtime ──────────────────────────────────────
FROM jlesage/baseimage-gui:ubuntu-${UBUNTU_VERSION}-v4

ENV DEBIAN_FRONTEND=noninteractive
COPY --from=builder /out/llm-wiki.deb /tmp/llm-wiki.deb
# The .deb declares the WebKitGTK/GTK runtime deps; apt resolves them.
# jq seeds the settings store; CJK/emoji fonts cover the bundled UI locales;
# python3 runs the VSDA-backed web sign-in service.
# add-pkg (base image helper) provides the transient /etc/passwd that package
# maintainer scripts need; the image generates the real one at runtime.
RUN add-pkg \
        /tmp/llm-wiki.deb jq ca-certificates curl xdg-utils python3 \
        fonts-noto-core fonts-noto-cjk fonts-noto-color-emoji \
        libgl1-mesa-dri gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    && rm -rf /var/lib/apt/lists/* /tmp/llm-wiki.deb

COPY src-tauri/icons/icon.png /tmp/llm-wiki-icon.png
RUN install_app_icon.sh "file:///tmp/llm-wiki-icon.png" || echo "favicon generation skipped"; \
    rm -f /tmp/llm-wiki-icon.png

# Web sign-in uses VSDA Deep Agent accounts: replace the stock webauth binary
# (a symlink, removed first so COPY cannot write through it) and login page.
RUN rm -f /etc/services.d/webauth/run /etc/services.d/webauth/params \
        /opt/noVNC/login/index.html
COPY docker/rootfs/ /
RUN chmod +x /startapp.sh /etc/cont-init.d/*.sh \
        /etc/services.d/webauth/run /etc/services.d/webauth/params \
    && python3 -m py_compile /opt/llm-wiki-auth/vsda_webauth.py \
    # Control bar: account button next to Logout, opening VSDA Deep Agent.
    && sed -i 's#<a class="btn shadow-none p-0 px-0 noVNC_hidden" href="logout"#<a class="btn shadow-none p-0 px-0 me-2" href="LLM_WIKI_VSDA_APP_URL/" target="_blank" rel="noopener" title="Manage account in VSDA Deep Agent" aria-label="Manage account in VSDA Deep Agent" id="llm_wiki_account_button"><i class="fas fa-user-cog fa-fw"></i></a>&#' \
        /opt/noVNC/index.html \
    && grep -q 'id="llm_wiki_account_button"' /opt/noVNC/index.html \
    # Sharp graph edges and text: resize the X display to the browser viewport
    # (1:1 pixels) instead of downscaling 1920x1080 when the window is smaller,
    # and stream at the highest JPEG quality. Touch devices still use 'scale'.
    && sed -i -E \
        -e 's#window\.inner(Width|Height) < 0\.8 \* UI\.webData\.applicationWindow(Width|Height)#false#' \
        -e "s#UI\.initSetting\('quality', 6\);#UI.initSetting('quality', 9);#" \
        /opt/noVNC/app/ui.js \
    && ! grep -q 'window.innerWidth < 0.8' /opt/noVNC/app/ui.js \
    && grep -q "UI.initSetting('quality', 9);" /opt/noVNC/app/ui.js

ENV APP_NAME="LLM Wiki" \
    KEEP_APP_RUNNING=1 \
    # No GPU in the container: force software rendering for WebKitGTK.
    WEBKIT_DISABLE_COMPOSITING_MODE=1 \
    WEBKIT_DISABLE_DMABUF_RENDERER=1 \
    LIBGL_ALWAYS_SOFTWARE=1

VOLUME ["/config", "/wikis"]

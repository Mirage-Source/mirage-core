#!/bin/sh
# Prints the stamp for the binary a `docker compose build` is about to make:
#   <short sha of HEAD>          the tree is exactly HEAD
#   <short sha of HEAD>-dirty    anything differs, including untracked files
#   unknown                      not a git checkout
# `git describe --dirty` ignores untracked files, but `COPY . .` puts them in the
# image, so a build with a new untracked source file would wrongly look clean.
# Files matched by .gitignore are not seen here either; keep build outputs out of the tree.
#
#   BUILD_SHA=$(sh scripts/build_sha.sh) docker compose up -d --build mirage-core mirage-telnet
sha=$(git rev-parse --short HEAD 2>/dev/null) || { echo unknown; exit 0; }
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "${sha}-dirty"
else
    echo "${sha}"
fi

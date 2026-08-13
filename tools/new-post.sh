#!/usr/bin/env bash
#
# Scaffold a new Chirpy post in _posts/ and an image folder in assets/img/posts/.
#
# Usage: tools/new-post.sh "Recursively fuzzing MS-RPC structures"
#        tools/new-post.sh "Some title" --draft

set -eu

TITLE="${1-}"
if [[ -z "$TITLE" ]]; then
  echo "Usage: $0 \"Post title\" [--draft]" >&2
  exit 1
fi

DIR="_posts"
[[ "${2-}" == "--draft" ]] && DIR="_drafts"

cd "$(dirname "$0")/.."

# Slugify: lowercase, non-alphanumerics to dashes, squeeze and trim dashes.
SLUG="$(echo "$TITLE" |
  tr '[:upper:]' '[:lower:]' |
  sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"

DATE="$(date +%F)"
STAMP="$(date '+%F %H:%M:%S %z')"
FILE="$DIR/$DATE-$SLUG.md"
IMG_DIR="assets/img/posts/$SLUG"

if [[ -e "$FILE" ]]; then
  echo "Already exists: $FILE" >&2
  exit 1
fi

mkdir -p "$DIR" "$IMG_DIR"

cat >"$FILE" <<EOF
---
title: "$TITLE"
description:
author: remco
date: $STAMP
categories: [Research, Windows]
tags: [Research]
pin: false
math: false
mermaid: false
image:
  path: /$IMG_DIR/1.png
---

EOF

echo "Created $FILE"
echo "Images   $IMG_DIR/"

#!/bin/sh
set -x -e
git submodule update --init
mkdir -p m4

RECONF_DIRS="./ \
  ./src/ThirdParty/libqb \
  ./src/ThirdParty/libsodium \
  ./src/ThirdParty/pgl"

for reconf_dir in $RECONF_DIRS; do
    autoreconf -i -s --no-recursive "$reconf_dir"
done

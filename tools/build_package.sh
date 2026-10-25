#!/usr/bin/env bash
# Build the conda package (conda.recipe/recipe.yaml) into output/noarch/,
# then run its test in a fresh environment: rattler-build installs the
# package with its dependencies only and runs conda.recipe/test_package.mojo
# there, with no -I src. Extra arguments go to rattler-build.
#
# The package's version must be the workspace's (pixi.toml), so the two
# cannot drift apart.
set -eu
cd "$(dirname "$0")/.."
want=$(sed -n 's/^version = "\(.*\)"$/\1/p' pixi.toml | head -1)
have=$(sed -n 's/^  version: "\(.*\)"$/\1/p' conda.recipe/recipe.yaml | head -1)
if [[ -z "$want" || "$want" != "$have" ]]; then
  echo "FAIL version: pixi.toml says '$want', conda.recipe/recipe.yaml '$have'"
  exit 1
fi
rattler-build build --recipe conda.recipe/recipe.yaml --output-dir output \
  -c https://conda.modular.com/max -c conda-forge "$@"
ls -l output/noarch/mojo-net-"$want"-*.conda

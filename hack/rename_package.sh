#!/bin/bash
set -ex
ORIGINAL="github.com\/starlingai\/flock\/go\/pkg"
NEW="github.com\/jlewi\/monogo"
find ./ -name "*.go"  -exec  sed -i ".bak" "s/${ORIGINAL}/${NEW}/g" {} ";"
sed -i ".bak" "s/${ORIGINAL}/${NEW}/g" go.mod
find ./ -name "*.bak" -exec rm {} ";"

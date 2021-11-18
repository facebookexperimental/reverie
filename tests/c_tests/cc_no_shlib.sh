#!/bin/bash
# (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

# fbmake will pass --install-dir and --fbcode--dir while
# buck won't pass it. So drop all arguments except for the last two
while [[ $# -gt 1 ]]; do
    shift;
done

src=$1

shift

path=$INSTALL_DIR
[[ ! -d $path ]] && mkdir -p "$path";

output_file=$(basename "$src")
output=$INSTALL_DIR/${output_file%.*}

echo "compiling $output from $src"

cc=clang.par

${cc} -nostdlib -o "$output" "$src" "$*"

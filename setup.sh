#!/bin/bash

libs=(
    argparse
    requests
    colorama
)

for lib in "${libs[@]}"; do
    pip install "$lib"
done

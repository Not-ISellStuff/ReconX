#!/bin/bash

libs=(
    argparse
    requests
    colorama
    nmap
    urllib.parse
)

for lib in "${libs[@]}"; do
    pip install "$lib"
done

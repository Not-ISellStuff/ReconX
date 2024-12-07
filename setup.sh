#!/bin/bash

libs=(
    numpy
    pandas
    matplotlib
    requests
    flask
)

echo "Installing Python libraries..."
for lib in "${libs[@]}"; do
    pip install "$lib"
done

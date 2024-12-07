#!/bin/bash

libs=(
    numpy
    pandas
    matplotlib
    requests
    flask
)

for lib in "${libs[@]}"; do
    pip install "$lib"
done

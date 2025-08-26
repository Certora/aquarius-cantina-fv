#!/bin/bash

# Usage: ./run_all_integrity.sh
# Run all integrity verification configs

if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0"
    echo "Run all integrity verification configs for the fees_collector contract"
    exit 0
fi

for config in fees_collector_integrity_*_verified.conf; do
    echo "Running: $config"
    certoraSorobanProver "$config"   
done
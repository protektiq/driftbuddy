#!/bin/bash

INPUT_DIR="/mnt/d/driftbuddy/test_data/iac_example"
OUTPUT_DIR="/mnt/d/driftbuddy/test_data/output"

mkdir -p "$OUTPUT_DIR"

docker run --rm \
  -v "$INPUT_DIR":/input \
  -v "$OUTPUT_DIR":/output \
  checkmarx/kics:latest \
  scan -p /input -o /output -t terraform -f json

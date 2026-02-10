#!/usr/bin/env bash
set -e

docker run -d \
  --name "$1" \
  -p "127.0.0.1:$4:6901" \
  --shm-size=2g \
  -e VNC_PW=password \
  -e VNCOPTIONS="-disableBasicAuth" \
  -e LAUNCH_URL="$2" \
  -e PROXY_URL="$3" \
  -e SEOCROMOM_TOKEN="${5:-}" \
  proxylogin-chrome:latest

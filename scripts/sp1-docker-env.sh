#!/usr/bin/env sh

# Succinct's gnark wrapper image is currently published for linux/amd64 only.
# Docker Desktop can run it under emulation on Apple Silicon, but Docker must be
# told which platform to pull before SP1 invokes `docker run` internally.
if [ -z "${DOCKER_DEFAULT_PLATFORM:-}" ] && [ "$(uname -s)" = "Darwin" ]; then
  case "$(uname -m)" in
    arm64|aarch64)
      export DOCKER_DEFAULT_PLATFORM=linux/amd64
      ;;
  esac
fi

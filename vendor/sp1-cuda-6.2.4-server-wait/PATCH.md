# Local SP1 CUDA startup patch

This directory is `sp1-cuda` 6.2.4 with one intentionally narrow change:
`CudaClientInner::connect_inner` waits up to 60 seconds (600 × 100 ms) for the
same SDK-managed `sp1-gpu-server` child to create its Unix socket. Upstream
waits only about one second (10 × 100 ms), which is shorter than cold CUDA
initialization on some benchmark hosts.

No request, response, proving, setup, key-management, or cleanup behavior is
changed. The existing child handle remains owned by the SDK and retains its
original `kill_on_drop` lifecycle.

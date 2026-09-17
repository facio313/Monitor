# Monitor response truncation — 2026-09-09

The dashboard showed both “원격 측정 갱신 실패” and “수집 데이터가 아직 없습니다”
although the collector and application were healthy. At 19:55–19:57 KST,
production access logs recorded HTTP 200 for the failing dashboard requests.
The matching Nginx error entries reported `Permission denied` while opening
proxy temporary files. The worker account was `www-data`, while
`/var/lib/nginx/proxy` belonged to `nobody` with mode `0700`.

A direct 24-hour API response contained 613,107 bytes and valid JSON. The
affected proxy responses ended around 138–144 kB, after their successful status
headers had already been sent. This explains why readiness and direct-browser
checks passed while the public dashboard failed to parse its response.

Monitor now sends `X-Accel-Buffering: no` for its responses, including large
JavaScript assets. Nginx consumes this header and streams the response without
spilling it to proxy temporary files. This confines the fix to Monitor and
requires no shared proxy permission/configuration change or Nginx reload.
The dashboard also distinguishes a failed data request from an empty collector
snapshot in its explanatory copy.

Regression coverage includes dashboard, HTML, and JavaScript response headers
in `server/app.test.ts`, and an isolated Nginx transport test:

```sh
python3 -m unittest discover -s ops/tests -p test_nginx_response_streaming.py -v
```

The transport test reproduces HTTP 200 followed by a truncated JSON body when
the private test proxy directory is unwritable, then verifies byte-for-byte
delivery of the same 4 MiB response with the streaming header. It does not load
production proxy configuration or use production temporary directories.

For deployment verification, check full response-body delivery and JSON
parsing through the proxy, not only HTTP status. The streaming header is
normally hidden by Nginx and need not appear in the public response. Existing
collector data, authentication settings, and the previous image are retained.

## Production recovery evidence

The Monitor-only hotfix image
`ghcr.io/facio313/monitor:hotfix-response-streaming-20260909-1` was deployed at
20:04 KST. Its image ID is
`sha256:2824fbfd6fe04244dc407b9dca40256fa051083ef27a5b008c04dbfcbf4d5235`.
It preserves the previous production image's runtime and authentication
contract, replacing only the compiled application/client artifacts.

The real public dashboard request at 20:04:27 returned only 143,178 bytes and
the matching proxy permission error. The next automatic request at 20:05:28
returned all 613,155 bytes, with no new matching proxy error. The container
became healthy and the public readiness route returned HTTP 200.

Production browser verification rendered 8 charts and 11 panels with no
JavaScript error, refresh-failure notice, or empty-state panel. Direct complete
JSON readbacks for 1h, 24h, 7d, and 30d were fresh; the largest response was
2,079,475 bytes. Relevant checks passed: 39 application tests, 5 dashboard
tests, the isolated transport regression, both TypeScript checks, and the
production build.

Source changes are retained in this worktree; the hotfix image was built and
deployed locally, without publishing a registry tag or pushing Git changes.

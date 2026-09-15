# Security scope

NIDA is a local research demonstration, not a hardened public service.

- Bind to loopback, the default. Container examples publish only on loopback.
- Only load trusted model bundles. Pickled sklearn objects can execute code; checksums verify consistency with the manifest, not publisher identity.
- Do not use sensitive production telemetry for a public demonstration. Inference is local; the browser retains at most 80 flows and exports them only on user action.
- Browser access is same-origin. WebSocket origin validation is not authentication; command-line clients may omit Origin.
- Bodies, batches and in-process concurrency are bounded. There is no tenant isolation or public rate limiter.
- CSP, text-only DOM rendering, local assets and removal of wildcard CORS reduce the dashboard attack surface.
- Recommendations are advisory. No prediction triggers blocking.

Before public deployment, add authentication, TLS, an upstream request/rate limiter, telemetry governance, monitoring and external security review. Low-risk or unqueued flows are not certified safe.

Report vulnerabilities privately to the repository owner, or use GitHub private vulnerability reporting if enabled. Do not post credentials or private network flows in public issues.

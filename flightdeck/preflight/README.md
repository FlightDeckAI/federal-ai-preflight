# Federal.AI Deployment Preflight

A read-only manifest review for **Google AX** deployments. It gives AI infrastructure teams a repeatable, evidence-linked checklist before a cluster deployment.

## Run

Python 3.10+:

```bash
cd flightdeck/preflight
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python preflight.py examples/bounded.yaml --internal-host registry.internal
.venv/bin/python preflight.py examples/review-needed.yaml --output review.json
.venv/bin/python -m unittest -v
```

The bounded example returns exit `0`. The review-needed example returns exit `1` with findings; this is expected. Exit `2` means malformed/unsupported input structure or an execution error. [Committed example output](examples/review-needed-report.json).

## What it adds

| Check | Why it matters |
| --- | --- |
| Images without SHA-256 digests | Mutable artifacts undermine repeatable deployments |
| External image, Git, MCP and egress hosts | Exposes dependencies absent from an internal-host inventory |
| Wildcard egress | Identifies unbounded destinations |
| Missing workspace/gateway references | Finds incomplete manifest bundles |
| Literal credential-like environment variables | Flags unsafe secret placement without printing values |
| Mutable Git references and debug mode | Calls out deployment review items |
| Registry discovery and disconnected model providers | Makes unresolved offline assumptions visible |

Profiles: `connected` permits external hosts but still checks artifact pinning and other rules; `restricted` requires exact operator-supplied internal hosts; `disconnected` additionally blocks unverified model-provider assumptions. Repeat `--internal-host` and `--known-secret` to provide inventories. A name in an inventory is an operator assertion, not proof of network placement or secret existence.

Supports the inspected `ax.io/v1alpha1` Task, Workspace, Gateway and Model manifests. YAML aliases and duplicate keys are rejected. This is a focused rule set, not a complete AX schema validator. Resources not in the bundle are unresolved even if they may exist in a cluster.

## Validation and boundaries

Nine tests pass, including secret-value omission, duplicate YAML keys, aliases, disconnected-model behavior and missing references. Both CLI fixtures were exercised. No Kubernetes cluster is contacted; nothing is deployed or changed.

`passed_static_checks` means only that the implemented rules found no error-level findings. It does **not** mean safe, compliant, accredited, fully offline, deployable, or production ready. No image contents, DNS, network reachability, runtime traffic, credential validity or unmodeled dependencies are verified. AX APIs are evolving; the upstream baseline is recorded in [UPSTREAM.md](UPSTREAM.md).

## Credit

FlightDeckAI extension of [google/ax](https://github.com/google/ax), by Google and its contributors, Apache-2.0. Original licenses and notices are retained. Federal.AI is not presented as Google-affiliated.

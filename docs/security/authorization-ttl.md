# Authorization TTL policy

Remote session requests may ask for a lifetime, but they cannot choose the
maximum lifetime granted by Gateway. The daemon evaluates every request
against validated local policy before creating a session.

## Effective lifetime

For a requested duration `R` and capability profile `P`, Gateway computes:

```text
effective = min(max(R, 1 minute), profile_ceiling(P), risk_ceiling(risk(P)))
```

`risk(P)` is assigned by local configuration; it is not a risk claim supplied
by the remote caller. Both ceilings therefore remain local policy decisions.
Values below one minute are normalized to one minute. Values above either
ceiling are clamped, including `i64::MAX`, without duration arithmetic on the
untrusted integer.

The resulting `issued_at` and `expires_at` are persisted in the `sessions`
record. `expires_at` is the effective expiry exposed by the local IPC API and
shown as **Effective expiry** in the session approval UI. The daemon also logs
the requested and effective minute values when it creates the pending session.

## Defaults and rationale

| Capability profile | Local risk class | Profile ceiling | Risk ceiling | Effective default |
|---|---:|---:|---:|---:|
| `Inspect` | Low | 4 hours | 2 hours | 2 hours |
| `Design` | Normal | 2 hours | 1 hour | 1 hour |
| `Manufacturing` | High | 30 minutes | 15 minutes | 15 minutes |
| `Custom` | Critical | 5 minutes | 1 minute | 1 minute |

Risk ceilings are the primary baseline. Profile ceilings remain an independent
second bound, so loosening a risk ceiling cannot grant a broad profile more
than its own configured maximum. `Custom` defaults to Critical because it may
contain any capability. High- and critical-risk operations also retain the
separate per-operation **Allow Once** approval gate; a shorter session TTL does
not replace that control.

These defaults are intentionally explicit V1 hardening choices, not inferred
from upstream folklore.

## Configuration

The optional `[authorization_ttl]` table in `<data_dir>/config.toml` overrides
all defaults as one unit. A partial table, unknown key, unknown risk name, or
value outside `1..=525600` is a configuration error and prevents startup; the
daemon never silently falls back to defaults after a malformed policy.

```toml
[authorization_ttl]
low_risk_max_minutes = 120
normal_risk_max_minutes = 60
high_risk_max_minutes = 15
critical_risk_max_minutes = 1

[authorization_ttl.inspect]
max_minutes = 240
risk = "low"

[authorization_ttl.design]
max_minutes = 120
risk = "normal"

[authorization_ttl.manufacturing]
max_minutes = 30
risk = "high"

[authorization_ttl.custom]
max_minutes = 5
risk = "critical"
```

The one-year validation ceiling is an arithmetic and operational sanity bound,
not a default recommendation. Operators should choose shorter lifetimes for
their risk tolerance. TTL is defense in depth; explicit revocation remains the
immediate control for ending access.

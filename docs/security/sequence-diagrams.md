# Sequence Diagrams for Outbound Relay Security Contract

## Pairing Flow

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant SecureStore as Secure Storage (Local)
    participant PolicyEngine as Policy Engine (Local)

    Note over Gateway,Relay: Relay identity is derived only from the validated TLS server certificate, never from a relay-asserted device_id
    Gateway->>Gateway: complete TLS handshake and validate relay server certificate (PKI)
    Gateway->>Gateway: derive relay identity from validated certificate (SPKI fingerprint)
    Gateway->>Relay: pairing.begin (device_id, nonce)
    Relay->>Gateway: pairing.challenge (server_nonce)
    Gateway->>SecureStore: load device private key
    Gateway->>Gateway: sign(challenge + server_nonce + device_nonce)
    Gateway->>Relay: pairing.proof (signature, device_nonce)
    Relay->>Relay: verify signature using device_id's public key
    alt verification success
        Relay->>Gateway: pairing.result (paired=true)
        Gateway->>SecureStore: store pinned relay TLS identity as paired relay identity
        Note over Gateway,SecureStore: Source binding only. Grants no authorization, and an envelope device_id is only ever compared against the local DeviceIdentity
        Gateway->>PolicyEngine: create pending session
    else verification failure
        Relay->>Gateway: pairing.result (paired=false, reason)
    end
```

The paired relay identity is the pinned TLS certificate identity observed on the
handshake. It is never a `device_id` value supplied by the relay, and it carries
no authorization privileges (see
[outbound-relay-contract.md](./outbound-relay-contract.md#authentication-and-identity)).

## Session Request and Approval

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant PolicyEngine as Policy Engine (Local)
    participant User as Local User (UI/CLI)
    participant SessionStore as Session Store (Local)

    Relay->>Gateway: session.request (session_id, requested_workspaces, requested_capabilities)
    Gateway->>PolicyEngine: check session.request validity (envelope device_id == local DeviceIdentity, source == pinned relay TLS identity)
    Gateway->>PolicyEngine: create session record (pending approval)
    Gateway->>User: show approval request (session details)
    User->>Gateway: approve/reject session (via UI/CLI)
    alt approved
        Gateway->>PolicyEngine: mark session as approved
        Gateway->>Relay: session.decision (approved=true)
        Gateway->>SessionStore: persist session
    else rejected
        Gateway->>PolicyEngine: mark session as revoked
        Gateway->>Relay: session.decision (approved=false)
        Gateway->>SessionStore: persist session (revoked)
    end
```

## Operation Request Flow

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant PolicyEngine as Policy Engine (Local)
    participant AuditLog as Audit Log (Local)
    participant Keychain as Secure Storage (Private Keys)
    participant CoreBridge as Core Bridge (Local MCP)

    Relay->>Gateway: operation.request (session_id, correlation_id, tool_name, args)
    Gateway->>PolicyEngine: validate session_id exists and is approved
    Gateway->>PolicyEngine: check workspace authorization
    Gateway->>PolicyEngine: check capability authorization (tool_name)
    Gateway->>PolicyEngine: check operation args against pinned tool contract
    Gateway->>AuditLog: pre-execution audit record (must commit)
    Gateway->>Keychain: retrieve any required secrets (if tool declares needs)
    Gateway->>CoreBridge: forward operation.request (MCP tools/call)
    CoreBridge->>Gateway: operation.result (or error)
    Gateway->>AuditLog: post-execution audit record (outcome)
    Gateway->>Relay: operation.result (correlation_id, result or error)
```

## Reconnect After Timeout

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant ReconnectLogic as Reconnect Logic (Local)
    participant TransportState as Transport State (Local)

    Gateway->>Relay: (normal operation)
    Note over Gateway,Relay: Transport connection idle (no heartbeat within configured timeout)
    Relay->>Gateway: (no heartbeat)
    Gateway->>ReconnectLogic: detect missing heartbeat (timeout)
    Gateway->>TransportState: set state to Disconnected
    Gateway->>ReconnectLogic: initiate reconnect with backoff
    loop Reconnect Attempt
        Gateway->>Relay: TCP SYN (new connection)
        Relay->>Gateway: TCP SYN-ACK
        Gateway->>Relay: TLS ClientHello
        alt TLS success
            Relay->>Gateway: TLS ServerHello, Cert, etc.
            Gateway->>Relay: TLS Finished
            Gateway->>Gateway: validate relay certificate and re-check pinned relay TLS identity
            Gateway->>Relay: (TLS established)
            Gateway->>TransportState: set state to Connecting
            Gateway->>Relay: send any queued envelopes
            Gateway->>TransportState: set state to Connected
            Note over Gateway,TransportState: Reconnect restores the pipe only. No session or authorization state is recovered from the relay
        else TLS failure
            Gateway->>ReconnectLogic: increment attempt, calculate jittered delay
            Gateway->>ReconnectLogic: sleep(delay)
        end
    end
    Note over Gateway,Relay: After max attempts or success, reconnect ends
```

## Replay Attack Attempt

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant ReplayCache as Replay Cache (Required for production, mocked in tests)
    participant PolicyEngine as Policy Engine (Local)

    Relay->>Gateway: operation.request (session_id, correlation_id="old", timestamp="old")
    Note over Relay: (captured from previous session)
    Gateway->>PolicyEngine: check abs(now - timestamp) <= REPLAY_WINDOW (configurable, default 60s)
    alt timestamp outside validity window (stale or too far in future)
        Gateway->>PolicyEngine: reject immediately, fail closed (no processing, no forwarding)
        Gateway->>ReplayCache: do not cache the message_id (cache stays bounded to the window)
        Gateway->>Relay: (no response or error)
    else timestamp within validity window
        Gateway->>ReplayCache: lookup message_id in window
        alt message_id already seen in window (replay)
            Gateway->>PolicyEngine: reject as replay
            Gateway->>Relay: (no response or error)
        else message_id not seen (fresh message)
            Gateway->>ReplayCache: add message_id and evict entries outside the window
            Gateway->>PolicyEngine: process normally
            Gateway->>Relay: operation.result
        end
    end
```

Out-of-window messages are never processed. A message whose `timestamp` is
outside the validity window is rejected on arrival before any session, policy, or
core-bridge work, and before it enters the replay cache. Replay detection
therefore fails closed: an attacker gains nothing by delaying a captured
message, and evicting window-expired entries keeps the cache bounded (see
[outbound-relay-contract.md](./outbound-relay-contract.md#replay-ordering-and-idempotency-production-requirements)).

## Message Flooding Attempt

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant RateLimiter as Rate Limiter (Required for production, mocked in tests)
    participant Transport as Transport Layer

    Relay->>Gateway: message 1
    Relay->>Gateway: message 2
    ... (many messages)
    Gateway->>RateLimiter: check each message
    alt message within rate limit
        Gateway->>Transport: process normally
    else message exceeds rate limit
        Gateway->>RateLimiter: drop message
        Gateway->>Relay: (no response or optional error)
        Note over Gateway: If sustained, may close transport connection
    end
```

## Oversized Message Attempt

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant MessageValidator as Message Validator (Local)

    Relay->>Gateway: envelope with payload > MAX_SIZE
    Gateway->>MessageValidator: check envelope size
    alt size > MAX_SIZE
        Gateway->>MessageValidator: reject envelope
        Gateway->>Relay: (close connection or send error)
    else size <= MAX_SIZE
        Gateway->>MessageValidator: proceed to schema validation
    end
```

## Unknown Message Type Attempt

```mermaid
sequenceDiagram
    participant Gateway
    participant Relay
    participant MessageValidator as Message Validator (Local)

    Relay->>Gateway: envelope with message_type="unknown.type"
    Gateway->>MessageValidator: check message_type against registry
    alt message_type not in registry
        Gateway->>MessageValidator: reject envelope
        Gateway->>Relay: (close connection or send error)
    else message_type in registry
        Gateway->>MessageValidator: proceed to normal processing
    end
```

# zkVerify Agent Games — Proof Gatekeeper agent

Competition agent for [zkVerify Agent Games](https://agentgames.zkverify.io/events) (Season 01), track **Proof Gatekeeper**.

A public HTTPS endpoint the platform POSTs HMAC-signed task envelopes to. For every
task the agent:

1. verifies `x-agent-games-signature` over the **raw** request body (constant-time),
2. decides `APPROVE` / `REJECT` deterministically against the published rule set,
3. generates a **Groth16 proof** locally with snarkjs against the published
   `gatekeeper` circuit (BN128, 13 public signals) proving the decision followed
   the circuit's rule,
4. signs the response body with the same HMAC secret.

The circuit is the referee: it only admits `APPROVE` when every in-circuit check
passes, so a wrong decision cannot be proven.

## Decision order (fail closed)

| # | check | reject reason |
|---|-------|---------------|
| 0 | proof reference already accepted (out-of-circuit) | `PROOF_REUSED` |
| 1 | `proof_vk != registered_vk` | `VK_SUBSTITUTION` |
| 2 | `public_balance < minimum` | `THRESHOLD_MISMATCH` |
| 3 | `current_block >= expiry_block` | `EXPIRED_CONDITION` |
| 4 | `recipient != condition_recipient` | `RECIPIENT_MISMATCH` |
| 5 | `amount > max_transfer` | `AMOUNT_OVERFLOW` |
| – | all pass | `APPROVE` / `VALID_CONDITION` |

`PROOF_REUSED` carries no proof: it is the only rejection that happens outside the
circuit, and the circuit cannot prove a decision it never evaluated.

## Run

```bash
npm install
cp .env.example .env         # fill AGENT_GAMES_HMAC_SECRET from the dashboard
AGENT_GAMES_HMAC_SECRET=... PORT=8787 npm start
```

Expose it over HTTPS at the registered path (e.g. `https://host/agent`) and rotate
the secret once from the dashboard, then run preflight.

## Local harness

```bash
node tools/test_local.mjs http://127.0.0.1:8787 <hmac-secret>
```

Replays a preflight + one task per trap variety, including a replayed proof
reference and a bad-signature request. Expected: every response signature valid,
one proof per provable verdict (13 public signals), bad signature → 401.

## Layout

- `src/server.js` — transport, HMAC, decision logic, proving, idempotent task store
- `circuits/` — published `gatekeeper.wasm`, `gatekeeper_final.zkey`, verification key
- `tools/test_local.mjs` — signed envelope replay harness
- `tools/probe_rule.mjs` — proves which decisions the circuit will accept

Secrets are never committed: the HMAC secret comes from the environment only.

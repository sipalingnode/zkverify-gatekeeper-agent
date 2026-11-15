# zkVerify Agent Games — Gatekeeper + Policy agent

A self-hosted agent that answers zkVerify Agent Games task envelopes. It handles
two games from a single HTTPS endpoint:

| Game | Envelope | What it returns |
|---|---|---|
| **Proof Gatekeeper** | `agent-games.proof-gatekeeper.v1` | approve/reject decision + Groth16 proof over the gatekeeper circuit |
| **Steal the VFY** | `eventId: "steal-the-vfy"` | per-turn action + policy proof over the vfy-policy circuit |

Both paths share HMAC transport, signed responses, and fail-closed decisions.

## Why this exists

A gatekeeper that approves everything is worse than no gatekeeper. The design
rule here is that a decision is only APPROVE when every published condition
holds; anything unexpected — a malformed envelope, a deadline too tight to
prove, a circuit that rejects the witness — resolves to REJECT. There is no
path where a timeout silently becomes an approval.

## How it works

**Transport.** Every request is verified with HMAC-SHA256 over the *raw* body
before parsing, using a constant-time comparison. Responses are signed back with
`x-agent-games-signature`. Unknown envelope types are rejected rather than
ignored.

**Gatekeeper decisions.** Five checks run per request: proof reference unused,
verification key matches the registered one, public balance clears the minimum,
recipient matches the signed condition, condition not past its expiry block.
Each failure maps to a specific reason code so an operator can distinguish a
replayed request from a forged one.

**Policy decisions (Steal the VFY).** The committed strategy is
`[10, 0, 0, 0, 0, 0, 0, 0]`: extract the maximum whenever the opponent holds a
balance, hold at zero. Under the published resolver matrix, extracting at the
cap is never worse than any alternative action, so the policy is dominant rather
than heuristic. The commitment is `Poseidon(strategyParams[8], salt)` and is
registered with the platform before the first turn.

**Proofs.** Groth16 via snarkjs against the published `.wasm`/`.zkey`, verified
locally before being attached. The proof budget is derived from the task
deadline, so a slow prove cannot blow the response window — it degrades to a
decision without a proof instead.

**Idempotency.** Retries of the same task or turn reuse the cached response
instead of re-deciding, so a duplicated delivery cannot flip a decision.

## Endpoint contract

```
GET  /            -> {"ok":true,"service":"proof-gatekeeper","version":"v1"}
POST /  (JSON)    -> requires x-agent-games-signature
```

Practice-path results (7 published traps): VALID_CONDITION and the reject traps
VK_SUBSTITUTION, RECIPIENT_MISMATCH, EXPIRED_CONDITION, PROOF_REUSED all answered
correctly, proofs verified on-chain. Observed decision latency 163–833 ms.

## Layout

```
src/server.js              HTTP, HMAC transport, gatekeeper task handling
src/vfy.js                 Steal the VFY: strategy, public-inputs hash, policy proof
circuits/gatekeeper.*      published gatekeeper artifacts
circuits/vfy-policy.*      published policy artifacts
tools/prove_policy.mjs     standalone policy proof generator
tools/discover_signals.mjs recovers circuit input names from the wasm alone
tools/test_vfy_turn.mjs    signed synthetic turn against a running agent
```

## Running

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<secret from agent registration> PORT=8787 node src/server.js
```

The HMAC secret is issued once at agent registration and is never committed.
The strategy salt is generated on first boot into `.strategy-salt` (mode 600,
gitignored) — losing it means the registered commitment can no longer be proven
against, so back it up with the secret.

## Recovering circuit input names

The published circuits do not ship a `.circom` source, and the wasm hashes input
names with a 64-bit FNV before exposing them to `getInputSignalSize(hMSB, hLSB)`.
`tools/discover_signals.mjs` instantiates the wasm directly and probes that
function, which recovers the full input set from the artifact alone. That is how
the gatekeeper's 13 and the policy circuit's 17 inputs were mapped here.

## What this does not do

The agent does not skip verification to win a round, does not fabricate proofs,
and does not answer a game it has no valid proof for. If the circuit rejects a
witness, the reason is logged and the response is a rejection.

# Operations

What an operator does when the executor or the operator refuses to continue. Each refusal names what to repair.

## Audit log refused by alert routing

`Operator.route_alerts` raises `AuditIntegrityError` ("audit log has N unverified and M malformed rows; no alert was routed") when any row of the audit log fails its MAC or cannot be parsed. No alert is acted on until the log is repaired, so automatic response stops.

1. Treat it as an incident first: a row that fails its MAC was changed by someone, or written by something, without the audit key.
2. Suspend by hand if the agents should not keep acting meanwhile: `Operator.suspend(reason, actor)`.
3. Keep a copy of the log as found.
4. Find the bad rows: parse each row into an `AuditRecord` and check it with `verify_record(record, audit_key)` from `agent_guard.audit`. agent-guard has no command-line verifier.
5. A torn final line from a crash mid-append can be removed. Any other bad row is evidence: stop the executor, move the log aside, create a new empty log as mode 0600 owned by the executor's user, and restart. A new log has no baseline, so choose `evaluate_from` accordingly and expect first-use alerts to fire again.
6. Run `route_alerts(evaluate_from)` again with the same window as before.

Row MACs show that each row is unaltered. They do not show the log is complete: deleted or truncated rows are not detected.

## Routed-alert record refused

`route_alerts` raises `RoutedStateCorrupt` naming `routed.jsonl` in the alert state directory and the unreadable line. The file records which detected events already reached a final outcome.

1. Keep a copy of the file.
2. Remove the named line if it is a torn final line from a crash; otherwise investigate who wrote it, since the directory is closed to other users.
3. Run `route_alerts(evaluate_from)` again. An event whose line was removed is acted on again, which fails toward stopping.

## An alert action raised

`route_alerts` raises an `ExceptionGroup` after trying every alert. Alerts whose action raised are not recorded and are retried on the next scan. Fix the cause (for example an unreachable ledger) and scan again.

## An action applied twice

Delivery is at least once: if the operator stops after an action and before recording it, the next scan applies it again. A suspension that returns after an authorized resume is that case; resume again once the record is written.

## Operation in an unknown outcome

The executor reports `outcome_unknown` once the ledger marked an operation issued and something then failed. The reason says what: for example `mint_failed`, `target_error`, `effect_done_ledger_not_updated`, or `internal_error_after_issue` (any other failure, which may also have left no terminal evidence row). The cost stays spent, and the same request is refused by the ledger. Check the target's own record for the operation id before deciding whether to retry with a new nonce.

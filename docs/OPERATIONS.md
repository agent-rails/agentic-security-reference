# Operations

Recovery steps for executor and operator failures.

## Audit log refused by alert routing

`Operator.route_alerts` raises `AuditIntegrityError` ("audit log has N unverified and M malformed rows; no alert was routed") when any row of the audit log fails its MAC or cannot be parsed. No alert is acted on until the log is repaired, so automatic response stops.

1. Treat a failed MAC as a possible integrity incident. The row was changed or written without a valid audit key.
2. If agents must stop while the log is investigated, call `Operator.suspend(reason, actor)`.
3. Keep a copy of the log as found.
4. Parse each row into an `AuditRecord` and check it with `verify_record(record, audit_key)` from `agent_guard.audit`. agent-guard has no command-line verifier.
5. After preserving the original log, remove a torn final line only if a crash during append explains it. For any other bad row, stop the executor, move the log aside, create a new empty log owned by the executor's user with mode 0600, and restart. Choose `evaluate_from` for the new log; first-use alerts may fire again because the baseline is gone.
6. Run `route_alerts(evaluate_from)` again with the same window as before.

Row MACs show that each retained row is unaltered. They do not detect deleted or truncated rows.

## Routed-alert record refused

`route_alerts` raises `RoutedStateCorrupt` naming `routed.jsonl` in the alert state directory and the unreadable line. The file records which detected events already reached a final outcome.

1. Keep a copy of the file.
2. Remove the named line if it is a torn final line from a crash; otherwise investigate who wrote it, since the directory is closed to other users.
3. Run `route_alerts(evaluate_from)` again. An event whose line was removed is acted on again, which fails toward stopping.

## An alert action raised

`route_alerts` raises an `ExceptionGroup` after trying every alert. Alerts whose action raised are not recorded and are retried on the next scan. Fix the cause (for example an unreachable ledger) and scan again.

## An action applied twice

Delivery is at least once. If the operator stops after an action and before recording it, the next scan applies it again. A suspension that returns after an authorized resume is that case; resume again once the record is written.

## Operation in an unknown outcome

After `mark_issued` returns, mint failures and errors during or after the target call report `outcome_unknown`. Its reason may be `mint_failed`, `target_error`, `effect_done_ledger_not_updated`, or `internal_error_after_issue`. Other injector refusals remain refusals. A missing terminal evidence row does not prove the effect did not run. For an unknown outcome, cost remains spent and a same-nonce retry reports `already_outcome_unknown` without running the effect again. Check the target's own record for the operation id before considering a new nonce, which would create a new operation.

A crash inside `mark_issued` may persist the issued state but return a refusal before minting. In that case, retrying with the same nonce can mint the one credential and perform the effect once. The test `tests/test_executor.py::test_retry_after_a_crash_between_marking_issued_and_minting_runs_once` exercises this path.

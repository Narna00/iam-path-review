# IAM Path Review

Find separation-of-duties conflicts caused by direct or inherited access in normalized identity exports. Every result includes witness paths showing how a user or service principal acquires the conflicting actions.

## Run

Python 3.12+, no runtime dependencies:

```sh
python iam_paths.py iam.example.json --as-of 2026-10-20
python -m unittest discover -v
```

The example shows a payment creator inheriting payment approval through nested finance groups. It exits 1 because the conflict is open.

## Model

`principals` contain unique IDs and a kind (`user`, `service`, or `group`). `memberships` point from a member to an inherited group. `grants` associate an exact action and exact resource ID with a principal. `rules` identify combinations of two or more actions that should not coexist on the same resource. Breadth-first traversal produces shortest inheritance witnesses and terminates on membership cycles.

Exceptions bind an exact principal/rule/resource triple and require `approved_by`, `reason`, and `expires_on`. They remain effective through the expiry calendar date. Expired exceptions remain visible as open findings. An accepted exception is recorded risk acceptance, not evidence that the entitlement was removed.

## Boundary

This intentionally small entitlement model is not an AWS, Azure, GCP, or directory authorization simulator. It does not interpret wildcards, deny policies, conditions, role trust, session policy, tenant boundaries, resource hierarchy, or runtime activation. Normalize *effective* grants upstream with an appropriate provider-specific evaluator. Do not load raw cloud IAM policy documents into this schema or interpret a clean result as proof of least privilege.

The analyzer uses exact resource equality so permissions on development and production cannot be combined into a false conflict. Review export completeness, nested membership semantics, dormant accounts, and exception approvals separately. Work from sanitized snapshots; no live identity API calls are made.

## Output

JSON results include principal, resource, rule ID, exception status, and per-action witness paths. Exit 0 means no open modeled conflict, 1 means at least one open conflict, and 2 means malformed input or an I/O error.

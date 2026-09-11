---
name: mass-assignment
description: Mass assignment testing for unauthorized field binding and privilege escalation via API parameters
---

# Mass Assignment

Mass assignment binds client-supplied fields directly into models/DTOs without field-level allowlists. It commonly leads to privilege escalation, ownership changes, and unauthorized state transitions in modern APIs and GraphQL.

## Attack Surface

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies
- Model binding in controllers/resolvers; ORM create/update helpers
- Writable nested relations, sparse/patch updates, bulk endpoints

## Key Vulnerabilities

### Privilege Escalation

- Set role/isAdmin/permissions during signup/profile update
- Toggle admin/staff flags where exposed

### Ownership Takeover

- Change ownerId/accountId/tenantId to seize resources
- Move objects across users/tenants

### Feature Gate Bypass

- Enable premium/beta/feature flags via flags/features fields
- Raise limits/seatCount/quotas

### Billing and Entitlements

- Modify plan/price/prorate/trialEnd or creditBalance
- Bypass server recomputation

### Nested and Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller's scope

## Validation

1. Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller
2. Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value
3. Demonstrate consistency across at least two encodings or channels
4. For nested/bulk, show that protected fields are written within child objects or array elements
5. Quantify impact (e.g., role flip, cross-tenant move, quota increase) and reproducibility

## False Positives

- Server recomputes derived fields (plan/price/role) ignoring client input
- Fields marked read-only and enforced consistently across encodings
- Only UI-side changes with no persisted effect

## Impact

- Privilege escalation and admin feature access
- Cross-tenant or cross-account resource takeover
- Financial/billing manipulation and quota abuse
- Policy/approval bypass by toggling verification or status flags

## Pro Tips

1. Build a sensitive-field dictionary per resource and fuzz systematically
2. Always try alternate shapes and encodings; many validators are shape/CT-specific
3. For GraphQL, diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields
4. Inspect SDKs/mobile apps for hidden field names and nested write examples
5. Prefer minimal PoCs that prove durable state changes; avoid UI-only effects

## Summary

Mass assignment is eliminated by explicit mapping and per-field authorization. Treat every client-supplied attribute—especially nested or batch inputs—as untrusted until validated against an allowlist and caller scope.

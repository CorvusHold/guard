# Fine-Grained Authorization (FGA) – Spec Draft

This spec extends tenant-scoped roles/permissions with fine-grained, object-level authorization.

## Concepts
- Subject: user or group within a tenant.
- Object: a resource instance (type + id), e.g., settings (tenant), user:123, session:abc.
- Action (Permission): operation on an object, e.g., settings:write, users:manage, sessions:revoke.
- Tuple: relation linking subject ↔ action ↔ object. Example: (user:U, settings:write, tenant:T).

## Goals
- Per-tenant, per-object decisions: allow/deny based on tuples and role-derived permissions.
- Keep backward compatibility with existing role checks while migrating to authorize(object, action).
- Efficient evaluation with caching; deterministic & auditable.

## Non-Goals
- Full Zanzibar graph traversal (groups-of-groups with deep recursion) in v1.
- Attribute-based policies or time-based conditions in v1 (can add later via condition blobs).

---

## Data Model
- permissions (global)
  - id, key (unique), description, timestamps
- roles (tenant-scoped)
  - id, tenant_id, name (unique per tenant), description, timestamps
- role_permissions (scoped to type)
  - role_id, permission_id, scope_type ENUM('tenant','type','object')
  - resource_type NULLABLE (required when scope_type='type' or 'object')
  - resource_id NULLABLE (required when scope_type='object')
  - unique(role_id, permission_id, scope_type, resource_type, resource_id)
- user_roles (tenant-scoped)
  - user_id, tenant_id, role_id, unique(user_id, tenant_id, role_id)
- acl_tuples (direct grants)
  - id, tenant_id, subject_type ENUM('user','group'), subject_id
  - permission_id (or permission_key TEXT for immutability),
  - object_type TEXT, object_id TEXT (NULL allowed to mean tenant-wide)
  - created_by, timestamps
  - indices: by (tenant_id, subject_type, subject_id), and by (tenant_id, object_type, object_id)
- groups (basic, first-class)
  - id, tenant_id, name (unique per tenant), description NULLABLE, timestamps
  - indices: unique(tenant_id, name)
- group_members
  - group_id, user_id, unique(group_id, user_id), timestamps

Notes
- role_permissions supports fine scopes without duplicating tuples for every user.
- acl_tuples allow direct, instance-level grants (e.g., delegate settings:write to a specific user).

---

## Decision API
- POST /v1/auth/authorize
  - Body: { tenant_id, subject: { user_id } | { group_id }, action: string, object: { type: string, id?: string } }
  - Response: { allowed: boolean, reason?: string }
- Semantics (v1): allow if any are true
  1) Direct tuple grant exists in acl_tuples for (tenant, user, action, object) with the most specific match:
     - object match order: (type+id) > (type only) > (tenant-wide/null)
  2) A role assigned to the user grants the action per role_permissions with the same match specificity.
  3) Special-owner rule: owner role gets wildcard within tenant (compatibility window).
- Deny by default.

Caching
- Cache resolved permissions for a user (and groups) per tenant at three tiers: tenant-wide, per type, per object-id.
- Invalidate on: user role changes, group membership changes, role permission changes, tuple mutations.
- Token perms: include a compact `perms` claim in tokens to accelerate common checks and UI hints.
  - Scope encoded: `settings:write@tenant`, `users:manage@user:*`, `sessions:revoke@session:*`.
  - Object-id–specific grants are not encoded in the token; server-side authorize() remains canonical for object-level.
  - Server-side cache is the source of truth; token perms are an optimization and for UI gating hints.

---

## HTTP Enforcement Changes
- Replace role checks with authorize calls:
  - Settings write → authorize(action='settings:write', object={type:'settings', id:tenant_id})
  - Admin Users list/manage → users:read / users:manage on object={type:'user', id:*} (type-scope)
  - Sessions list/revoke → sessions:read / sessions:revoke on object={type:'session', id:*}
- Keep role-based fallback during migration: allow if role==admin/owner OR authorize()==true.

Design guidance
- Keep the canonical permission catalog lean and stable. Favor a small set of clear, composable keys.
- Permissions are configurable per tenant via role mappings and tuples; avoid exploding the surface with overly granular keys that harm UX.
- Separation of concerns: product areas should own their permission keys; a central catalog prevents drift.

---

## Admin APIs (Management)
- Roles CRUD (tenant-scoped):
  - GET/POST/PATCH/DELETE /v1/auth/admin/roles
- Role Permissions:
  - GET /v1/auth/admin/roles/:id/permissions
  - POST /v1/auth/admin/roles/:id/permissions { permissions: [{ key, scope_type, resource_type?, resource_id? }] }
- ACL Tuples (direct grants):
  - GET /v1/auth/admin/acl/tuples?subject=...&object=...&action=...
  - POST /v1/auth/admin/acl/tuples { subject, action, object }
  - DELETE /v1/auth/admin/acl/tuples/:id
- Read-only Permissions Catalog:
  - GET /v1/auth/admin/permissions (list canonical permission keys)

- Groups (basic):
  - GET/POST/DELETE /v1/auth/admin/groups
  - POST/DELETE /v1/auth/admin/groups/:id/members { user_id }

Security
- Protect all admin endpoints with: authorize('roles:manage', object={type:'tenant', id:tenant_id}) or equivalent admin permission.

---

## SDK (TS)
- Add client.authorize({ tenantId, action, object: { type, id? } }): Promise<{ allowed: boolean }>
- Add role/permission/tuple management methods mirroring admin APIs.
- Add group management methods: listGroups, createGroup, deleteGroup, addMember, removeMember.
- DTOs include claimed perms in token/me for coarse UI hints; server-side authorize() is canonical.

---

## Example Mappings (Defaults)
- owner → wildcard within tenant (migration-only), then explicit set:
  - settings:read/write (tenant)
  - users:read/manage (type user)
  - sessions:read/revoke (type session)
- admin →
  - users:read/manage (type user)
  - sessions:read/revoke (type session)
- member →
  - settings:read (tenant)

---

## Seeding
- Seed canonical permissions: settings:read/write, users:read/manage, sessions:read/revoke
- For each tenant seeded: create roles owner/admin/member and attach default scoped permissions.
 - Groups: none by default; tests/fixtures may create sample groups.

---

## Testing
- Unit: resolution precedence (object-id > type > tenant), cache invalidation, deny-by-default.
- Integration: admin can grant tuple; member gains access only to that object; revoke removes access.
- Integration (groups): assign user to group; grant permission to group; user inherits access; removing membership revokes access.
- E2E (Playwright):
  - Member cannot save settings → grant tuple (settings:write, tenant) → can save → revoke → cannot save.
  - Admin manages users with type-scope permission; member denied.

---

## Rollout
1) Ship tuples + scoped role permissions + authorize API.
2) Update endpoints to use authorize() with role fallback.
3) Add perms claim to tokens; ensure UI uses it for hints while relying on server authorization for object-level.
4) Migrate UI to permission-based guards.
5) Remove role fallback once stable.

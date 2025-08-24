# Tenant-Configurable Roles + Permissions (RBAC v2)

## Goals
- Introduce a first-class permissions model with tenant-configurable role→permission mappings.
- Keep existing roles (e.g., owner, admin) but enforce access via permissions.
- Minimal friction for existing API/UI; provide a safe migration path.

## Non-Goals
- Attribute- or context-based authorization (ABAC/OPA) – out of scope.
- Cross-tenant roles – all roles are scoped to a tenant.

---

## Data Model & Migrations
- permissions (global)
  - id (uuid, pk)
  - key (text, unique, e.g., "settings:write")
  - description (text)
  - created_at, updated_at
- roles (tenant-scoped)
  - id (uuid, pk)
  - tenant_id (uuid, fk tenants)
  - name (text, unique per tenant, e.g., "owner", "admin", "member")
  - description (text)
  - created_at, updated_at
- role_permissions (mapping)
  - role_id (fk roles)
  - permission_id (fk permissions)
  - unique(role_id, permission_id)
- user_roles (if not already normalized; otherwise keep current storage but mirror into this table)
  - user_id (uuid, fk users)
  - tenant_id (uuid, fk tenants)
  - role_id (fk roles)
  - unique(user_id, tenant_id, role_id)
- user_permissions (optional direct grants; v1: skip or add later)
  - user_id, tenant_id, permission_id, unique(...)

Migration Steps
1) Create new tables and indices.
2) Seed canonical permissions:
   - settings:read, settings:write
   - users:read, users:manage
   - sessions:read, sessions:revoke
   - auth:me, auth:introspect (if needed for service boundaries)
3) For each tenant, create default roles if not present: owner, admin, member.
4) Map roles → permissions defaults:
   - owner: [settings:read, settings:write, users:read, users:manage, sessions:read, sessions:revoke]
   - admin: [users:read, users:manage, sessions:read, sessions:revoke]
   - member: [settings:read]
5) Backfill current user role arrays into user_roles table. Maintain backward-compatible role names.

---

## Service Layer
- Add `AuthorizationService` (or extend auth service) with:
  - ResolveUserPermissions(ctx, userID, tenantID) []Permission
  - HasPermission(ctx, userID, tenantID, permKey) bool
  - CRUD for roles and permissions (tenant-scoped for roles, global for permissions)
  - Assign/Remove permissions to role
  - Assign/Remove roles to user (reuse current UpdateUserRoles under the hood)
- Caching: Cache resolved permission keys per (tenantID,userID). Invalidate on role/permission changes.

---

## Token & Introspection
- On login/refresh, include compact `perms` claim (array of permission keys) for fast checks in the API layer.
- Maintain `roles` for backward compatibility. Gate checks transition: role OR permission → permission-only.
- Invalidate token or rotate on role/permission changes (short TTL or versioning). Initial iteration: rely on refresh TTL + cache flush.

---

## HTTP API (Admin)
- Roles
  - GET /v1/auth/admin/roles?tenant_id=... (list)
  - POST /v1/auth/admin/roles (create) { name, description }
  - PATCH /v1/auth/admin/roles/:id (update)
  - DELETE /v1/auth/admin/roles/:id
- Role Permissions
  - GET /v1/auth/admin/roles/:id/permissions
  - POST /v1/auth/admin/roles/:id/permissions (set/replace) { permissions: string[] }
- Users
  - Keep existing: POST /v1/auth/admin/users/:id/roles (set roles)
  - Optional: POST /v1/auth/admin/users/:id/permissions (direct grants) – later

RBAC on Admin endpoints (via permissions):
- roles:manage
- roles:read
- permissions:read

Map existing endpoints to permissions:
- Settings PUT: settings:write
- Settings GET: settings:read
- Admin Users list / update names / block|unblock: users:manage (write) and users:read (read)
- Sessions list / revoke: sessions:read / sessions:revoke

---

## SDK Changes (TS)
- Types: Permission, Role, RolePermission mappings.
- New client methods:
  - listRoles, createRole, updateRole, deleteRole
  - listPermissions (global), setRolePermissions
  - getUserRoles, setUserRoles (reuse existing semantics)
- Include `perms?: string[]` in token/me DTOs.

---

## Next.js Example App
- New admin UI: `/admin/roles`
  - List roles (tenant), create/delete role
  - Edit role permissions (checkboxes of canonical permission keys)
- Update UI guards to use permission checks (server-side in API routes, client-side for conditional links):
  - e.g., hide Settings link unless user has settings:read; allow save only if settings:write.
- Keep current Admin Users page; ensure it loads roles via API and respects permissions.

---

## Seeding & Dev Experience
- Extend `examples_setup` (docker-compose) to:
  - Ensure canonical permissions
  - Ensure default roles and mappings per seeded tenant
  - Seed admin user with role=admin; optionally owner user
- Extend `cmd/seed`:
  - `seed permissions` (idempotent global)
  - `seed role --tenant-id --name ... --permissions p1,p2`

---

## Testing Plan
- Unit tests:
  - Permission resolution across role mappings and cache behavior
  - HasPermission logic edge cases (no roles, mixed tenant)
- Integration tests (Go):
  - Admin CRUD roles, set role permissions, and enforcement on protected endpoints
  - Backward compatibility: role-based user still authorized (in transitional phase)
- E2E (Playwright):
  - Owner can edit settings (settings:write); member cannot
  - Admin can manage users (users:manage)
  - Roles UI: create role, assign permissions, verify enforcement

---

## Security & Validation
- Validate names/keys: lowercase kebab/colon, max length, reserved words (owner, admin, member)
- Enforce tenant scoping on every admin endpoint
- Deny empty permission sets for critical roles (owner must retain superset)
- Rate limit admin endpoints; audit logs (future)

---

## Performance
- Cache user permission keys in Redis keyed by tenant+user; TTL 5–15m
- Optional: include `perms` in JWT; prefer server-side cache first iteration

---

## Rollout Strategy
1) Ship schema + services + admin APIs; keep endpoints checking (role OR permission)
2) Backfill & seed defaults; add UI for roles management
3) Switch enforcement to permissions-only after confidence window

---

## Work Breakdown
- Migrations: tables, indices, seed canonical permissions
- Service: permission resolver, CRUD, cache
- API: admin endpoints, update checks on existing routes
- SDK: methods & types; bump version
- Example UI: roles admin page; update guards
- Seeding: examples_setup + seed CLI extensions
- Tests: unit, integration, e2e

---

## Acceptance Criteria
- Default tenants have roles mapped to canonical permissions
- All protected endpoints enforce via permissions (not raw roles)
- Admin can manage roles and permissions via API (and example UI)
- Playwright tests pass: owner can save settings; member forbidden; admin manages users

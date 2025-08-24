-- +goose Up
-- +goose StatementBegin
-- Seed canonical permissions and default role mappings. Backfill legacy users.roles -> user_roles per tenant.

-- 1) Canonical permissions
INSERT INTO permissions (key, description)
VALUES
  ('settings:read', 'Read application/tenant settings'),
  ('settings:write', 'Update application/tenant settings'),
  ('users:read', 'Read users list and profiles'),
  ('users:manage', 'Manage users (update, block/unblock, roles)'),
  ('sessions:read', 'Read sessions'),
  ('sessions:revoke', 'Revoke sessions'),
  ('roles:read', 'Read roles and role permissions'),
  ('roles:manage', 'Manage roles and role permissions'),
  ('permissions:read', 'List canonical permission keys')
ON CONFLICT (key) DO UPDATE SET updated_at = now();

-- 2) Create default roles per tenant (owner, admin, member)
DO $$
DECLARE t RECORD; r_owner UUID; r_admin UUID; r_member UUID; BEGIN
  FOR t IN SELECT id FROM tenants LOOP
    -- owner
    INSERT INTO roles (tenant_id, name, description)
    VALUES (t.id, 'owner', 'Tenant owner role')
    ON CONFLICT (tenant_id, name) DO NOTHING;
    SELECT id INTO r_owner FROM roles WHERE tenant_id = t.id AND name = 'owner';

    -- admin
    INSERT INTO roles (tenant_id, name, description)
    VALUES (t.id, 'admin', 'Tenant admin role')
    ON CONFLICT (tenant_id, name) DO NOTHING;
    SELECT id INTO r_admin FROM roles WHERE tenant_id = t.id AND name = 'admin';

    -- member
    INSERT INTO roles (tenant_id, name, description)
    VALUES (t.id, 'member', 'Tenant member role')
    ON CONFLICT (tenant_id, name) DO NOTHING;
    SELECT id INTO r_member FROM roles WHERE tenant_id = t.id AND name = 'member';

    -- Map canonical permissions to roles (idempotent)
    -- owner: everything
    INSERT INTO role_permissions (role_id, permission_id, scope_type, resource_type, resource_id)
    SELECT r_owner, p.id, 'tenant', NULL, NULL FROM permissions p
    ON CONFLICT (role_id, permission_id, scope_type, resource_type, resource_id) DO NOTHING;

    -- admin: users read/manage, sessions read/revoke, roles read
    INSERT INTO role_permissions (role_id, permission_id, scope_type, resource_type, resource_id)
    SELECT r_admin, p.id, x.scope_type, x.resource_type, x.resource_id
    FROM permissions p
    JOIN (
      VALUES
        ('users:read',   'type',    'user',    NULL),
        ('users:manage', 'type',    'user',    NULL),
        ('sessions:read','type',    'session', NULL),
        ('sessions:revoke','type',  'session', NULL),
        ('roles:read',   'tenant',  NULL,      NULL)
    ) AS x(key, scope_type, resource_type, resource_id) ON x.key = p.key
    ON CONFLICT (role_id, permission_id, scope_type, resource_type, resource_id) DO NOTHING;

    -- member: settings read
    INSERT INTO role_permissions (role_id, permission_id, scope_type, resource_type, resource_id)
    SELECT r_member, p.id, 'tenant', NULL, NULL FROM permissions p WHERE p.key = 'settings:read'
    ON CONFLICT (role_id, permission_id, scope_type, resource_type, resource_id) DO NOTHING;
  END LOOP;
END $$;

-- 3) Backfill legacy users.roles into normalized user_roles per tenant
-- Strategy: for each (user, tenant) pair in user_tenants, create role records for any role name present
-- in users.roles if not existing for that tenant, then link via user_roles.
DO $$
DECLARE r RECORD; role_name TEXT; role_id_var UUID; BEGIN
  -- Create missing role rows per tenant for any discovered legacy role name
  FOR r IN
    SELECT DISTINCT ut.tenant_id, unnest(u.roles) AS role_name
    FROM users u
    JOIN user_tenants ut ON ut.user_id = u.id
    WHERE array_length(u.roles, 1) IS NOT NULL
  LOOP
    INSERT INTO roles (tenant_id, name)
    VALUES (r.tenant_id, r.role_name)
    ON CONFLICT (tenant_id, name) DO NOTHING;
  END LOOP;

  -- Link users to roles via user_roles
  FOR r IN
    SELECT u.id AS user_id, ut.tenant_id, unnest(u.roles) AS role_name
    FROM users u
    JOIN user_tenants ut ON ut.user_id = u.id
    WHERE array_length(u.roles, 1) IS NOT NULL
  LOOP
    SELECT id INTO role_id_var FROM roles WHERE tenant_id = r.tenant_id AND name = r.role_name;
    IF role_id_var IS NOT NULL THEN
      INSERT INTO user_roles (user_id, tenant_id, role_id)
      VALUES (r.user_id, r.tenant_id, role_id_var)
      ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING;
    END IF;
  END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Best-effort cleanup of seeded data; does not remove user_roles or ad-hoc roles.
DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE name IN ('owner','admin','member'));
DELETE FROM roles WHERE name IN ('owner','admin','member');
DELETE FROM permissions WHERE key IN (
  'settings:read','settings:write','users:read','users:manage','sessions:read','sessions:revoke','roles:read','roles:manage','permissions:read'
);
-- +goose StatementEnd

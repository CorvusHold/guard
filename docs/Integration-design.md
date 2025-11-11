# 🧱 Application Database Design with Guard Integration

Core Principle: Reference, Don’t Duplicate

Golden Rule:

Store Guard’s UUIDs as references — let Guard own all authentication data.

⸻

🗂️ Application Database Schema

Pattern 1: Basic Multi-Tenant Tables

Example: projects table in your application

CREATE TABLE projects (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Guard references (NOT foreign keys to Guard DB)
    tenant_id UUID NOT NULL,  -- From Guard JWT token
    owner_id UUID NOT NULL,   -- Guard user_id

    -- Application data
    name TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'active',

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()

);

-- Critical: Index on tenant_id for performance
CREATE INDEX idx_projects_tenant ON projects(tenant_id);

-- Optional: Composite index for user queries
CREATE INDEX idx_projects_tenant_owner ON projects(tenant_id, owner_id);

⸻

Pattern 2: Multi-User Collaboration

Documents with multiple collaborators:

CREATE TABLE documents (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
tenant_id UUID NOT NULL,
created_by UUID NOT NULL, -- Guard user_id

    title TEXT NOT NULL,
    content TEXT,

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()

);

-- Collaborators junction table
CREATE TABLE document_collaborators (
document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
user_id UUID NOT NULL, -- Guard user_id
tenant_id UUID NOT NULL, -- For isolation
role TEXT NOT NULL DEFAULT 'viewer', -- editor, viewer, etc.

    PRIMARY KEY (document_id, user_id),
    CHECK (tenant_id IS NOT NULL)

);

CREATE INDEX idx_doc_collab_user ON document_collaborators(user_id);
CREATE INDEX idx_doc_collab_tenant ON document_collaborators(tenant_id);

⸻

Pattern 3: Denormalized User Data (Performance Optimization)

To display user info without constant Guard API calls:

CREATE TABLE tasks (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
tenant_id UUID NOT NULL,

    -- Source of truth
    assignee_id UUID NOT NULL,  -- Guard user_id

    -- Denormalized for display
    assignee_email TEXT,
    assignee_name TEXT,
    assignee_avatar_url TEXT,

    title TEXT NOT NULL,
    status TEXT DEFAULT 'todo',

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()

);

CREATE INDEX idx_tasks_assignee ON tasks(assignee_id);
CREATE INDEX idx_tasks_tenant ON tasks(tenant_id);

Keep denormalized data in sync:
• Update via Guard webhooks (if available)
• Refresh periodically via API
• Update when user profile changes in Guard

⸻

🧩 Understanding Guard’s User–Tenant Model

Key Insight:

Users are global, identities are per-tenant.

┌─────────────────────────────────────────────────────────┐
│ Guard Database │
│ │
│ users (global) │
│ ┌────────────┬──────────┬────────────┐ │
│ │ id (UUID) │ is_active│ first_name │ │
│ ├────────────┼──────────┼────────────┤ │
│ │ user-123 │ true │ John │ │
│ └────────────┴──────────┴────────────┘ │
│ │
│ auth_identities (email per tenant) │
│ ┌────────┬─────────┬──────────┬────────────────────┐ │
│ │user_id │tenant_id│ email │ password_hash │ │
│ ├────────┼─────────┼──────────┼────────────────────┤ │
│ │user-123│tenant-A │john@a.com│ $2a$10$... │ │
│ │user-123│tenant-B │john@b.com│ $2a$10$... │ │
│ └────────┴─────────┴──────────┴────────────────────┘ │
│ │
│ user_tenants (membership) │
│ ┌────────────┬──────────────┐ │
│ │ user_id │ tenant_id │ │
│ ├────────────┼──────────────┤ │
│ │ user-123 │ tenant-A │ │
│ │ user-123 │ tenant-B │ │
│ └────────────┴──────────────┘ │
└─────────────────────────────────────────────────────────┘

Implications:
• Same user_id can exist across multiple tenants
• Always filter by both tenant_id and user_id
• Email ≠ reliable identifier (can differ per tenant)

⸻

📊 Data Access Patterns

Pattern A: Tenant-Scoped Queries (Most Common)

Go Example

func (h \*Handler) ListProjects(c echo.Context) error {
tenantID, \_ := middleware.GetTenantID(c)
var projects []Project
err := h.db.Where("tenant_id = ?", tenantID).Find(&projects).Error
return c.JSON(200, projects)
}

TypeScript Example

async function getProjects(tenantId: string) {
const result = await db.query(
'SELECT \* FROM projects WHERE tenant_id = $1',
[tenantId]
);
return result.rows;
}

⸻

Pattern B: User-Scoped Queries

func (h \*Handler) GetMyProjects(c echo.Context) error {
tenantID, _ := middleware.GetTenantID(c)
userID, _ := middleware.GetUserID(c)

    var projects []Project
    err := h.db.Where("tenant_id = ? AND owner_id = ?", tenantID, userID).
        Find(&projects).Error

    return c.JSON(200, projects)

}

⸻

Pattern C: Cross-Tenant Admin Queries (Rare)

func (h \*Handler) ListAllProjects(c echo.Context) error {
if !isSuperAdmin(c) {
return echo.ErrForbidden
}

    var projects []Project
    err := h.db.Find(&projects).Error
    return c.JSON(200, projects)

}

⸻

🔐 Database Security: Row-Level Security (RLS)

If using PostgreSQL, enable RLS for automatic tenant isolation:

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON projects
USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_policy ON documents
USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_policy ON tasks
USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

App Code Example (Go):

func (h *Handler) setTenantContext(c echo.Context, db *gorm.DB) \*gorm.DB {
tenantID, \_ := middleware.GetTenantID(c)
return db.Exec("SET LOCAL app.current_tenant_id = ?", tenantID.String())
}

⸻

👤 Getting User Information

Option 1: From JWT Token (Fast)

userID := middleware.GetUserID(c)
tenantID := middleware.GetTenantID(c)
email := middleware.GetEmail(c)

project := Project{
ID: uuid.New(),
TenantID: tenantID,
OwnerID: userID,
Name: "New Project",
}
db.Create(&project)

⸻

Option 2: From Guard API (Fresh Data)

Go Example

func (h *Handler) GetUserProfile(userID uuid.UUID) (*UserProfile, error) {
resp, err := h.guardClient.Me(context.Background())
if err != nil {
return nil, err
}
return &UserProfile{
ID: resp.ID,
Email: resp.Email,
FirstName: resp.FirstName,
LastName: resp.LastName,
}, nil
}

TypeScript Example

async function enrichUserData(userId: string) {
const userProfile = await guardClient.me();
await db.query(
'UPDATE tasks SET assignee_email = $1, assignee_name = $2 WHERE assignee_id = $3',
    [userProfile.data.email, `${userProfile.data.first_name} ${userProfile.data.last_name}`, userId]
);
}

⸻

🛍️ Complete Example: E-Commerce App

Tenants → Stores
Users → Employees/Admins

Products

CREATE TABLE products (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
tenant_id UUID NOT NULL,
created_by UUID NOT NULL, -- Guard user_id

    name TEXT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    inventory_count INTEGER DEFAULT 0,

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()

);

Orders

CREATE TABLE orders (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
tenant_id UUID NOT NULL,

    customer_email TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    processed_by UUID,  -- Guard user_id

    total_amount DECIMAL(10,2) NOT NULL,
    status TEXT DEFAULT 'pending',

    created_at TIMESTAMPTZ DEFAULT now()

);

Audit Log

CREATE TABLE audit_log (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
tenant_id UUID NOT NULL,
user_id UUID NOT NULL,

    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NOT NULL,

    user_email TEXT NOT NULL,

    created_at TIMESTAMPTZ DEFAULT now()

);

CREATE INDEX idx_products_tenant ON products(tenant_id);
CREATE INDEX idx_orders_tenant ON orders(tenant_id);
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_user ON audit_log(user_id);

⸻

🔄 Migration Strategy: Adding Guard to an Existing App 1. Add Guard References

ALTER TABLE users ADD COLUMN guard_user_id UUID;
ALTER TABLE users ADD COLUMN guard_tenant_id UUID;

    2.	Sync Users to Guard (via API)
    3.	Phase Out Local Auth

ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users DROP COLUMN email;

Example Migration Script

async function migrateUsers() {
const existingUsers = await db.query('SELECT \* FROM users WHERE guard_user_id IS NULL');

for (const user of existingUsers.rows) {
const guardResp = await guardClient.passwordSignup({
tenant_id: process.env.GUARD_TENANT_ID,
email: user.email,
password: generateTemporaryPassword(),
first_name: user.first_name,
last_name: user.last_name
});

    await db.query(
      'UPDATE users SET guard_user_id = $1, guard_tenant_id = $2 WHERE id = $3',
      [guardResp.data.user_id, process.env.GUARD_TENANT_ID, user.id]
    );

    await guardClient.sendPasswordResetEmail(user.email);

}
}

⸻

✅ Database Design Checklist

DO
• Store tenant_id and user_id as UUIDs
• Always filter by tenant_id for isolation
• Index tenant_id columns for performance
• Use Guard’s JWT for context
• Fetch user profile from Guard API when needed

DON’T
• Create foreign keys to Guard’s database
• Store passwords or MFA data
• Duplicate Guard’s user logic
• Use email as a primary identifier
• Allow cross-tenant data leaks

Security Tips
• Extract IDs from validated JWTs
• Never trust client-provided IDs
• Implement RLS in PostgreSQL
• Always validate tenant ownership before data mutations

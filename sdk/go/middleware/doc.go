// Package middleware provides Echo framework middleware for Guard authentication and authorization.
//
// # Overview
//
// This package enables secure backend API protection by validating Guard access tokens
// and enforcing RBAC (Role-Based Access Control) policies. It's designed for Go/Echo backends
// that need to validate tokens issued by Guard.
//
// # Architecture
//
// The middleware operates in this flow:
//
//	1. Client sends request with Guard token
//	   └─ Authorization: Bearer <token>  (or guard_access_token cookie)
//	   └─ X-Tenant-ID: <tenant-id> (optional)
//
//	2. RequireAuth middleware validates token
//	   └─ Calls Guard's Introspect API
//	   └─ Extracts user, tenant, roles, email
//	   └─ Stores in Echo context
//
//	3. Downstream handlers use context helpers
//	   └─ GetUserID(), GetTenantID(), GetRoles()
//	   └─ Or authorization middleware checks permissions
//
//	4. RequireRole/RequirePermission enforce policy
//	   └─ Returns 403 if insufficient permissions
//
// # Token Sources
//
// The middleware supports two authentication modes:
//
// Bearer Token Mode (default):
//	- Token in Authorization header: "Authorization: Bearer <token>"
//	- Used with Guard's authMode: 'bearer'
//	- Frontend stores token in localStorage or memory
//
// Cookie Mode:
//	- Token in HTTP-only cookie: "guard_access_token"
//	- Used with Guard's authMode: 'cookie'
//	- Automatically handled by HTTP clients
//
// # Common Patterns
//
// # Pattern 1: Protect All Routes Under a Path
//
//	e := echo.New()
//	guardClient, _ := guard.NewClient("https://guard.example.com")
//
//	// All /api/* routes require authentication
//	api := e.Group("/api")
//	api.Use(middleware.RequireAuth(guardClient))
//	api.GET("/profile", profileHandler)
//	api.POST("/documents", createDocumentHandler)
//
// # Pattern 2: Admin-Only Routes
//
//	// Only admin role can access
//	admin := e.Group("/api/admin")
//	admin.Use(middleware.RequireAuth(guardClient))
//	admin.Use(middleware.RequireAdmin(guardClient))
//	admin.GET("/users", listUsersHandler)
//	admin.DELETE("/users/:id", deleteUserHandler)
//
// # Pattern 3: Multiple Roles (OR logic)
//
//	// User can have any of these roles
//	protected := e.Group("/api")
//	protected.Use(middleware.RequireAuth(guardClient))
//	protected.Use(middleware.RequireRole(guardClient, "editor", "admin"))
//	protected.DELETE("/:id", deleteHandler)
//
// # Pattern 4: Extract User Context
//
//	func profileHandler(c echo.Context) error {
//	    userID, _ := middleware.GetUserID(c)
//	    email, _ := middleware.GetEmail(c)
//	    roles, _ := middleware.GetRoles(c)
//
//	    // Use in your business logic
//	    return c.JSON(200, map[string]any{
//	        "user_id": userID,
//	        "email": email,
//	        "roles": roles,
//	    })
//	}
//
// # Pattern 5: Permission-Based Access
//
//	documents := e.Group("/api/documents")
//	documents.Use(middleware.RequireAuth(guardClient))
//	documents.POST("", middleware.RequirePermission(guardClient, "documents:create"), createDocHandler)
//	documents.PUT("/:id", middleware.RequirePermission(guardClient, "documents:update"), updateDocHandler)
//	documents.DELETE("/:id", middleware.RequirePermission(guardClient, "documents:delete"), deleteDocHandler)
//
// # Tenant Validation
//
// If your application is tenant-scoped, include the X-Tenant-ID header in requests:
//
//	headers := {
//	    "Authorization": "Bearer <token>",
//	    "X-Tenant-ID": "tenant-123"
//	}
//
// The middleware will verify that the token's tenant matches the header.
// If they don't match, the request returns 403 Forbidden.
//
// # Error Responses
//
// The middleware returns these HTTP status codes:
//
//	401 Unauthorized
//	  - Missing token
//	  - Invalid/malformed token
//	  - Token introspection failed
//	  - Token not active/expired
//	  - User not authenticated (RequireRole/RequirePermission without RequireAuth)
//
//	403 Forbidden
//	  - Tenant mismatch (X-Tenant-ID != token tenant)
//	  - User lacks required role(s)
//	  - User lacks required permission
//
//	500 Internal Server Error
//	  - Permission check API call failed
//
// # Frontend Integration
//
// With the TypeScript SDK, clients authenticate and send tokens:
//
//	import { GuardClient, WebLocalStorage } from '@corvushold/guard-sdk';
//
//	const guardClient = new GuardClient({
//	    baseUrl: 'https://guard.example.com',
//	    authMode: 'bearer',
//	    storage: new WebLocalStorage('myapp')
//	});
//
//	// Login
//	await guardClient.passwordLogin({
//	    email: user.email,
//	    password: user.password,
//	    tenant_id: 'tenant-123'
//	});
//
//	// Call protected backend API
//	const token = await guardClient.storage.getAccessToken();
//	const response = await fetch('https://api.example.com/api/profile', {
//	    headers: {
//	        'Authorization': `Bearer ${token}`,
//	        'X-Tenant-ID': 'tenant-123'
//	    }
//	});
//
// # Best Practices
//
// 1. Always apply RequireAuth first, before role/permission checks
// 2. Use X-Tenant-ID header for multi-tenant applications
// 3. Use RequireRole for coarse-grained access (admin, user, guest)
// 4. Use RequirePermission for fine-grained access (documents:read, documents:write)
// 5. Cache Guard's public key locally to reduce token introspection calls (future optimization)
// 6. Log failed authentication attempts for security monitoring
// 7. Keep token TTL short (15 minutes) and refresh regularly
// 8. Use HTTP-only cookies in production for maximum security
//
// # Performance Considerations
//
// Each protected request calls Guard's Introspect API to validate the token.
// To optimize performance:
//
// 1. Implement local JWT verification using Guard's public key
// 2. Cache Guard's public key with TTL
// 3. Use short-lived access tokens (refresh frequently)
// 4. Consider batch permission checks for permission-based access
//
// # Testing
//
// When testing handlers with middleware, use a mock GuardClient:
//
//	type mockClient struct {
//	    introspectFn func(ctx context.Context, token *string) (*guard.DomainIntrospection, error)
//	}
//
//	func (m *mockClient) Introspect(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
//	    return m.introspectFn(ctx, token)
//	}
//
//	// In test
//	client := &mockClient{
//	    introspectFn: func(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
//	        return &guard.DomainIntrospection{
//	            Active: boolPtr(true),
//	            UserId: stringPtr("user-123"),
//	            TenantId: stringPtr("tenant-123"),
//	            Roles: &[]string{"admin"},
//	        }, nil
//	    },
//	}
package middleware

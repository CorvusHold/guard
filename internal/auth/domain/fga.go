package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// --- Fine-Grained Authorization (FGA) domain scaffolding ---

// Group represents a basic tenant-scoped group.
type Group struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ErrDuplicateGroup indicates a group with the same unique key already exists.
var ErrDuplicateGroup = errors.New("group already exists")

// ACLTuple represents a direct permission grant to a subject on an object.
// This mirrors the schema in migrations: acl_tuples.
type ACLTuple struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	SubjectType  string // "user" | "group"
	SubjectID    uuid.UUID
	PermissionID uuid.UUID
	ObjectType   string
	ObjectID     *string
	CreatedBy    *uuid.UUID
	CreatedAt    time.Time
}

// FGARepository defines data access for groups, memberships, and ACL tuples.
type FGARepository interface {
	// Groups
	CreateGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, description string) (Group, error)
	ListGroups(ctx context.Context, tenantID uuid.UUID) ([]Group, error)
	DeleteGroup(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error

	// Group membership
	AddGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
	RemoveGroupMember(ctx context.Context, groupID uuid.UUID, userID uuid.UUID) error
	ListUserGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)

	// ACL tuples
	CreateACLTuple(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string, createdBy *uuid.UUID) (ACLTuple, error)
	DeleteACLTuple(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionID uuid.UUID, objectType string, objectID *string) error
	ListACLForUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]PermissionGrant, error)
	ListACLForGroups(ctx context.Context, tenantID uuid.UUID, groupIDs []uuid.UUID) ([]GroupPermissionGrant, error)
}

// FGADecisionService performs authorization decisions using roles, groups, and ACL tuples.
type FGADecisionService interface {
	// Authorize returns whether a subject is allowed to perform an action (permissionKey)
	// on an optional object (objectType/objectID) within a tenant. Implementations may
	// leverage caching and indexes for performance.
	Authorize(ctx context.Context, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID, permissionKey string, objectType string, objectID *string) (allowed bool, reason string, err error)
}

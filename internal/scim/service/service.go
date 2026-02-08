package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/corvusHold/guard/internal/scim/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service implements domain.Service backed by PostgreSQL.
type Service struct {
	pg *pgxpool.Pool
}

// New creates a new SCIM service.
func New(pg *pgxpool.Pool) *Service {
	return &Service{pg: pg}
}

func (s *Service) GetUser(ctx context.Context, tenantID uuid.UUID, userID string) (domain.SCIMUser, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return domain.SCIMUser{}, fmt.Errorf("invalid user id")
	}
	var firstName, lastName, email string
	var createdAt time.Time
	var blocked bool
	err = s.pg.QueryRow(ctx,
		`SELECT u.first_name, u.last_name, ai.email, u.created_at, u.blocked
		 FROM users u
		 JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = $1
		 JOIN auth_identities ai ON ai.user_id = u.id AND ai.tenant_id = $1
		 WHERE u.id = $2`,
		tenantID, uid,
	).Scan(&firstName, &lastName, &email, &createdAt, &blocked)
	if err != nil {
		return domain.SCIMUser{}, err
	}
	return domain.SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       uid.String(),
		UserName: email,
		Name:     domain.SCIMName{GivenName: firstName, FamilyName: lastName},
		Emails:   []domain.SCIMEmail{{Value: email, Type: "work", Primary: true}},
		Active:   !blocked,
		Meta: domain.SCIMMeta{
			ResourceType: "User",
			Created:      createdAt,
			LastModified: createdAt,
		},
	}, nil
}

func (s *Service) ListUsers(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (domain.SCIMListResponse, error) {
	// Normalize paging parameters to prevent negative OFFSET
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 100
	}

	baseQuery := `FROM users u
		 JOIN user_tenants ut ON ut.user_id = u.id AND ut.tenant_id = $1
		 JOIN auth_identities ai ON ai.user_id = u.id AND ai.tenant_id = $1`
	args := []interface{}{tenantID}
	argIdx := 2

	filterClause := ""
	if filter != "" && strings.Contains(filter, "userName eq") {
		parts := strings.SplitN(filter, "\"", 3)
		if len(parts) >= 2 {
			filterClause = fmt.Sprintf(" AND ai.email = $%d", argIdx)
			args = append(args, parts[1])
			argIdx++
		}
	}

	// Get total count for proper SCIM pagination
	var totalResults int
	countQuery := "SELECT COUNT(*) " + baseQuery + filterClause
	if err := s.pg.QueryRow(ctx, countQuery, args...).Scan(&totalResults); err != nil {
		return domain.SCIMListResponse{}, err
	}

	query := "SELECT u.id, u.first_name, u.last_name, ai.email, u.created_at, u.blocked " + baseQuery + filterClause
	query += fmt.Sprintf(" ORDER BY u.created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, count, startIndex-1)

	rows, err := s.pg.Query(ctx, query, args...)
	if err != nil {
		return domain.SCIMListResponse{}, err
	}
	defer rows.Close()

	var users []domain.SCIMUser
	for rows.Next() {
		var id uuid.UUID
		var firstName, lastName, email string
		var createdAt time.Time
		var blocked bool
		if err := rows.Scan(&id, &firstName, &lastName, &email, &createdAt, &blocked); err != nil {
			return domain.SCIMListResponse{}, err
		}
		users = append(users, domain.SCIMUser{
			Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			ID:       id.String(),
			UserName: email,
			Name:     domain.SCIMName{GivenName: firstName, FamilyName: lastName},
			Emails:   []domain.SCIMEmail{{Value: email, Type: "work", Primary: true}},
			Active:   !blocked,
			Meta:     domain.SCIMMeta{ResourceType: "User", Created: createdAt, LastModified: createdAt},
		})
	}
	return domain.SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: count,
		Resources:    users,
	}, nil
}

func (s *Service) CreateUser(ctx context.Context, tenantID uuid.UUID, user domain.SCIMUser) (domain.SCIMUser, error) {
	email := user.UserName
	if email == "" && len(user.Emails) > 0 {
		email = user.Emails[0].Value
	}
	if email == "" {
		return domain.SCIMUser{}, fmt.Errorf("email required")
	}

	userID := uuid.New()
	now := time.Now()

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return domain.SCIMUser{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx,
		`INSERT INTO users (id, first_name, last_name, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
		userID, user.Name.GivenName, user.Name.FamilyName, now,
	)
	if err != nil {
		return domain.SCIMUser{}, fmt.Errorf("create user: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO user_tenants (user_id, tenant_id) VALUES ($1, $2)`,
		userID, tenantID,
	)
	if err != nil {
		return domain.SCIMUser{}, fmt.Errorf("link tenant: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO auth_identities (id, user_id, tenant_id, email, password_hash) VALUES ($1, $2, $3, $4, '')`,
		uuid.New(), userID, tenantID, email,
	)
	if err != nil {
		return domain.SCIMUser{}, fmt.Errorf("create identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.SCIMUser{}, err
	}

	return domain.SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       userID.String(),
		UserName: email,
		Name:     user.Name,
		Emails:   []domain.SCIMEmail{{Value: email, Type: "work", Primary: true}},
		Active:   true,
		Meta:     domain.SCIMMeta{ResourceType: "User", Created: now, LastModified: now},
	}, nil
}

func (s *Service) UpdateUser(ctx context.Context, tenantID uuid.UUID, userID string, user domain.SCIMUser) (domain.SCIMUser, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return domain.SCIMUser{}, fmt.Errorf("invalid user id")
	}

	_, err = s.pg.Exec(ctx,
		`UPDATE users SET first_name = $1, last_name = $2, blocked = $3, updated_at = now() WHERE id = $4 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $5)`,
		user.Name.GivenName, user.Name.FamilyName, !user.Active, uid, tenantID,
	)
	if err != nil {
		return domain.SCIMUser{}, err
	}
	return s.GetUser(ctx, tenantID, userID)
}

func (s *Service) PatchUser(ctx context.Context, tenantID uuid.UUID, userID string, ops []domain.SCIMPatchOp) (domain.SCIMUser, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return domain.SCIMUser{}, fmt.Errorf("invalid user id")
	}

	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
			val, _ := op.Value.(string)
			switch strings.ToLower(op.Path) {
			case "name.givenname":
				_, err = s.pg.Exec(ctx, `UPDATE users SET first_name = $1, updated_at = now() WHERE id = $2 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $3)`, val, uid, tenantID)
			case "name.familyname":
				_, err = s.pg.Exec(ctx, `UPDATE users SET last_name = $1, updated_at = now() WHERE id = $2 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $3)`, val, uid, tenantID)
			case "active":
				boolVal := strings.EqualFold(val, "true") || val == ""
				if bv, ok := op.Value.(bool); ok {
					boolVal = bv
				}
				_, err = s.pg.Exec(ctx, `UPDATE users SET blocked = $1, updated_at = now() WHERE id = $2 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $3)`, !boolVal, uid, tenantID)
			case "username":
				_, err = s.pg.Exec(ctx, `UPDATE auth_identities SET email = $1 WHERE user_id = $2 AND tenant_id = $3`, val, uid, tenantID)
			default:
				// Handle nested name object: {"op":"replace","path":"name","value":{"givenName":"X","familyName":"Y"}}
				if strings.ToLower(op.Path) == "name" {
					if m, ok := op.Value.(map[string]interface{}); ok {
						if gn, ok := m["givenName"].(string); ok {
							if _, err = s.pg.Exec(ctx, `UPDATE users SET first_name = $1, updated_at = now() WHERE id = $2 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $3)`, gn, uid, tenantID); err != nil {
								return domain.SCIMUser{}, fmt.Errorf("patch op %s %s: %w", op.Op, op.Path, err)
							}
						}
						if fn, ok := m["familyName"].(string); ok {
							if _, err = s.pg.Exec(ctx, `UPDATE users SET last_name = $1, updated_at = now() WHERE id = $2 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $3)`, fn, uid, tenantID); err != nil {
								return domain.SCIMUser{}, fmt.Errorf("patch op %s %s: %w", op.Op, op.Path, err)
							}
						}
					}
				}
			}
		case "remove":
			switch strings.ToLower(op.Path) {
			case "name.givenname":
				_, err = s.pg.Exec(ctx, `UPDATE users SET first_name = '', updated_at = now() WHERE id = $1 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $2)`, uid, tenantID)
			case "name.familyname":
				_, err = s.pg.Exec(ctx, `UPDATE users SET last_name = '', updated_at = now() WHERE id = $1 AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = $2)`, uid, tenantID)
			}
		}
		if err != nil {
			return domain.SCIMUser{}, fmt.Errorf("patch op %s %s: %w", op.Op, op.Path, err)
		}
	}
	return s.GetUser(ctx, tenantID, userID)
}

func (s *Service) DeleteUser(ctx context.Context, tenantID uuid.UUID, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user id")
	}
	_, err = s.pg.Exec(ctx, `DELETE FROM user_tenants WHERE user_id = $1 AND tenant_id = $2`, uid, tenantID)
	return err
}

func (s *Service) GetGroup(ctx context.Context, tenantID uuid.UUID, groupID string) (domain.SCIMGroup, error) {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return domain.SCIMGroup{}, fmt.Errorf("invalid group id")
	}
	var name, description string
	var createdAt time.Time
	err = s.pg.QueryRow(ctx,
		`SELECT name, description, created_at FROM groups WHERE id = $1 AND tenant_id = $2`,
		gid, tenantID,
	).Scan(&name, &description, &createdAt)
	if err != nil {
		return domain.SCIMGroup{}, err
	}
	return domain.SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          gid.String(),
		DisplayName: name,
		Meta:        domain.SCIMMeta{ResourceType: "Group", Created: createdAt, LastModified: createdAt},
	}, nil
}

func (s *Service) ListGroups(ctx context.Context, tenantID uuid.UUID, filter string, startIndex, count int) (domain.SCIMListResponse, error) {
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 100
	}

	// Get total count for proper SCIM pagination
	var totalResults int
	if err := s.pg.QueryRow(ctx, `SELECT COUNT(*) FROM groups WHERE tenant_id = $1`, tenantID).Scan(&totalResults); err != nil {
		return domain.SCIMListResponse{}, err
	}

	rows, err := s.pg.Query(ctx,
		`SELECT id, name, created_at FROM groups WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, count, startIndex-1,
	)
	if err != nil {
		return domain.SCIMListResponse{}, err
	}
	defer rows.Close()

	var groups []domain.SCIMGroup
	for rows.Next() {
		var id uuid.UUID
		var name string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &createdAt); err != nil {
			return domain.SCIMListResponse{}, err
		}
		groups = append(groups, domain.SCIMGroup{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			ID:          id.String(),
			DisplayName: name,
			Meta:        domain.SCIMMeta{ResourceType: "Group", Created: createdAt, LastModified: createdAt},
		})
	}
	return domain.SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: count,
		Resources:    groups,
	}, nil
}

func (s *Service) CreateGroup(ctx context.Context, tenantID uuid.UUID, group domain.SCIMGroup) (domain.SCIMGroup, error) {
	id := uuid.New()
	now := time.Now()
	_, err := s.pg.Exec(ctx,
		`INSERT INTO groups (id, tenant_id, name, description, created_at) VALUES ($1, $2, $3, '', $4)`,
		id, tenantID, group.DisplayName, now,
	)
	if err != nil {
		return domain.SCIMGroup{}, err
	}
	return domain.SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          id.String(),
		DisplayName: group.DisplayName,
		Meta:        domain.SCIMMeta{ResourceType: "Group", Created: now, LastModified: now},
	}, nil
}

func (s *Service) UpdateGroup(ctx context.Context, tenantID uuid.UUID, groupID string, group domain.SCIMGroup) (domain.SCIMGroup, error) {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return domain.SCIMGroup{}, fmt.Errorf("invalid group id")
	}
	_, err = s.pg.Exec(ctx,
		`UPDATE groups SET name = $1 WHERE id = $2 AND tenant_id = $3`,
		group.DisplayName, gid, tenantID,
	)
	if err != nil {
		return domain.SCIMGroup{}, err
	}
	return s.GetGroup(ctx, tenantID, groupID)
}

func (s *Service) PatchGroup(ctx context.Context, tenantID uuid.UUID, groupID string, ops []domain.SCIMPatchOp) (domain.SCIMGroup, error) {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return domain.SCIMGroup{}, fmt.Errorf("invalid group id")
	}

	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
			val, _ := op.Value.(string)
			switch strings.ToLower(op.Path) {
			case "displayname":
				_, err = s.pg.Exec(ctx, `UPDATE groups SET name = $1 WHERE id = $2 AND tenant_id = $3`, val, gid, tenantID)
			case "members":
				// Members can be an array of {value: "userId"} objects
				if members, ok := op.Value.([]interface{}); ok {
					for _, m := range members {
						if mMap, ok := m.(map[string]interface{}); ok {
							if memberID, ok := mMap["value"].(string); ok {
								mid, parseErr := uuid.Parse(memberID)
								if parseErr == nil {
									if _, err = s.pg.Exec(ctx, `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, gid, mid); err != nil {
										return domain.SCIMGroup{}, fmt.Errorf("patch op %s %s: %w", op.Op, op.Path, err)
									}
								}
							}
						}
					}
				}
			}
		case "remove":
			switch strings.ToLower(op.Path) {
			case "displayname":
				// Cannot remove displayName per SCIM spec, ignore
			default:
				// Handle "members[value eq \"<uuid>\"]" removal
				if strings.HasPrefix(strings.ToLower(op.Path), "members") {
					// Extract UUID from filter expression
					if idx := strings.Index(op.Path, "\""); idx >= 0 {
						rest := op.Path[idx+1:]
						if end := strings.Index(rest, "\""); end >= 0 {
							memberID := rest[:end]
							mid, parseErr := uuid.Parse(memberID)
							if parseErr == nil {
								if _, err = s.pg.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, gid, mid); err != nil {
									return domain.SCIMGroup{}, fmt.Errorf("patch op %s %s: %w", op.Op, op.Path, err)
								}
							}
						}
					}
				}
			}
		}
		if err != nil {
			return domain.SCIMGroup{}, fmt.Errorf("patch op %s %s: %w", op.Op, op.Path, err)
		}
	}
	return s.GetGroup(ctx, tenantID, groupID)
}

func (s *Service) DeleteGroup(ctx context.Context, tenantID uuid.UUID, groupID string) error {
	gid, err := uuid.Parse(groupID)
	if err != nil {
		return fmt.Errorf("invalid group id")
	}
	_, err = s.pg.Exec(ctx, `DELETE FROM groups WHERE id = $1 AND tenant_id = $2`, gid, tenantID)
	return err
}

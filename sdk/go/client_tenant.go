package guard

import (
	"context"
	"errors"
)

// CreateTenantRequest contains the parameters for creating a new tenant.
type CreateTenantRequest struct {
	Name string
}

// TenantResponse represents a tenant's details.
type TenantResponse struct {
	ID        string
	Name      string
	IsActive  bool
	CreatedAt string
	UpdatedAt string
}

// CreateTenant creates a new tenant.
func (c *GuardClient) CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantResponse, error) {
	body := ControllerCreateTenantReq{Name: req.Name}
	resp, err := c.inner.PostApiV1TenantsWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, errors.New(resp.Status())
	}

	result := resp.JSON201
	tenant := &TenantResponse{}
	if result.Id != nil {
		tenant.ID = *result.Id
	}
	if result.Name != nil {
		tenant.Name = *result.Name
	}
	if result.IsActive != nil {
		tenant.IsActive = *result.IsActive
	}
	if result.CreatedAt != nil {
		tenant.CreatedAt = *result.CreatedAt
	}
	if result.UpdatedAt != nil {
		tenant.UpdatedAt = *result.UpdatedAt
	}

	return tenant, nil
}

// GetTenant retrieves a tenant by ID.
func (c *GuardClient) GetTenant(ctx context.Context, tenantID string) (*TenantResponse, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	resp, err := c.inner.GetApiV1TenantsIdWithResponse(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	tenant := &TenantResponse{}
	if resp.JSON200.Id != nil {
		tenant.ID = *resp.JSON200.Id
	}
	if resp.JSON200.Name != nil {
		tenant.Name = *resp.JSON200.Name
	}
	if resp.JSON200.IsActive != nil {
		tenant.IsActive = *resp.JSON200.IsActive
	}
	if resp.JSON200.CreatedAt != nil {
		tenant.CreatedAt = *resp.JSON200.CreatedAt
	}
	if resp.JSON200.UpdatedAt != nil {
		tenant.UpdatedAt = *resp.JSON200.UpdatedAt
	}

	return tenant, nil
}

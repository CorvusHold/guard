package guard

import (
	"context"
	"errors"
)

// EmailDiscoveryResult contains the result of email discovery for progressive login.
type EmailDiscoveryResult struct {
	Found      bool
	HasTenant  bool
	TenantID   *string
	TenantName *string
}

// TenantSummary represents a tenant that a user belongs to.
type TenantSummary struct {
	ID   string
	Name string
}

// PasswordSignup registers a new user with email/password and returns tokens on success (201 Created).
// It persists tokens into the configured TokenStore.
func (c *GuardClient) PasswordSignup(ctx context.Context, req ControllerSignupReq) (*ControllerAuthExchangeResp, error) {
	if req.TenantId == "" {
		req.TenantId = c.tenantID
	}
	resp, err := c.inner.PostApiV1AuthPasswordSignupWithResponse(ctx, nil, req)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 != nil {
		_ = c.persistTokens(ctx, resp.JSON201)
		return resp.JSON201, nil
	}
	return nil, errors.New(resp.Status())
}

// EmailDiscover performs email discovery for progressive login flows.
// It determines if an email exists and which tenant it belongs to.
func (c *GuardClient) EmailDiscover(ctx context.Context, email string, tenantID *string) (*EmailDiscoveryResult, error) {
	req := PostApiV1AuthEmailDiscoverJSONRequestBody{Email: email}
	resp, err := c.inner.PostApiV1AuthEmailDiscoverWithResponse(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	result := &EmailDiscoveryResult{
		Found:     false,
		HasTenant: false,
	}

	if resp.JSON200.Found != nil {
		result.Found = *resp.JSON200.Found
	}
	if resp.JSON200.HasTenant != nil {
		result.HasTenant = *resp.JSON200.HasTenant
	}
	if resp.JSON200.TenantId != nil {
		result.TenantID = resp.JSON200.TenantId
	}
	if resp.JSON200.TenantName != nil {
		result.TenantName = resp.JSON200.TenantName
	}

	return result, nil
}

// DiscoverTenants returns a list of tenants that a user with the given email belongs to.
// This is used for multi-tenant login selection flows.
func (c *GuardClient) DiscoverTenants(ctx context.Context, email string) ([]TenantSummary, error) {
	params := &GetApiV1TenantsParams{Q: &email}
	resp, err := c.inner.GetApiV1TenantsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var tenants []TenantSummary
	if resp.JSON200.Items != nil {
		for _, t := range *resp.JSON200.Items {
			summary := TenantSummary{}
			if t.Id != nil {
				summary.ID = *t.Id
			}
			if t.Name != nil {
				summary.Name = *t.Name
			}
			tenants = append(tenants, summary)
		}
	}

	return tenants, nil
}

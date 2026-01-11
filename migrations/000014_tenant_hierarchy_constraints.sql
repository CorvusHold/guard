-- +goose Up
-- +goose StatementBegin

-- Prevent self-parenting: a tenant cannot be its own parent
ALTER TABLE tenants ADD CONSTRAINT check_not_self_parent
    CHECK (parent_tenant_id IS NULL OR parent_tenant_id <> id);

-- Create function to detect cycles in tenant hierarchy
CREATE OR REPLACE FUNCTION check_tenant_hierarchy_cycle()
RETURNS TRIGGER AS $$
DECLARE
    cycle_detected BOOLEAN;
BEGIN
    -- For updates or inserts with parent_tenant_id, check for cycles
    IF NEW.parent_tenant_id IS NULL THEN
        RETURN NEW;
    END IF;

    -- Use recursive CTE to detect if setting this parent creates a cycle
    -- A cycle exists if we can reach the current tenant (NEW.id) by walking
    -- up the parent chain starting from NEW.parent_tenant_id
    WITH RECURSIVE ancestor_check AS (
        -- Start from the proposed parent
        SELECT
            id,
            parent_tenant_id,
            ARRAY[id] as path,
            1 as depth
        FROM tenants
        WHERE id = NEW.parent_tenant_id

        UNION ALL

        -- Walk up the parent chain
        SELECT
            t.id,
            t.parent_tenant_id,
            ac.path || t.id,
            ac.depth + 1
        FROM tenants t
        INNER JOIN ancestor_check ac ON t.id = ac.parent_tenant_id
        WHERE ac.depth < 100  -- Safety limit
          AND NOT t.id = ANY(ac.path)  -- Cycle detection: stop if we've seen this ID
    )
    SELECT EXISTS(
        SELECT 1 FROM ancestor_check WHERE id = NEW.id
    ) INTO cycle_detected;

    IF cycle_detected THEN
        RAISE EXCEPTION 'Cannot set parent_tenant_id: would create circular reference in tenant hierarchy';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger to tenants table for INSERT and UPDATE
CREATE TRIGGER enforce_tenant_hierarchy_no_cycles
    BEFORE INSERT OR UPDATE OF parent_tenant_id ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION check_tenant_hierarchy_cycle();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS enforce_tenant_hierarchy_no_cycles ON tenants;
DROP FUNCTION IF EXISTS check_tenant_hierarchy_cycle();
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS check_not_self_parent;
-- +goose StatementEnd

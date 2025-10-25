# Guard CLI

A command-line interface for managing Corvus Guard authentication service. Provides tenant management, user administration, settings configuration, and system monitoring capabilities.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/corvushold/guard.git
cd guard/cmd/guard-cli

# Build the CLI
go build -o guard-cli .

# Install globally (optional)
sudo mv guard-cli /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/corvushold/guard/cmd/guard-cli@latest
```

## Configuration

### Initialize Configuration

```bash
guard-cli config init
```

This will prompt you for:
- Guard API URL (default: http://localhost:8080)
- API authentication token
- Default tenant ID (optional)

### Configuration File

The CLI stores configuration in `~/.guard-cli.yaml`:

```yaml
api_url: "https://api.guard.example.com"
api_token: "your-api-token"
tenant_id: "default-tenant-id"
```

### Environment Variables

You can also configure using environment variables:

```bash
export GUARD_API_URL="https://api.guard.example.com"
export GUARD_API_TOKEN="your-api-token"
export GUARD_TENANT_ID="default-tenant-id"
```

## Usage

### Global Flags

- `--api-url`: Override API URL
- `--token`: Override API token
- `--tenant`: Override tenant ID
- `--verbose, -v`: Enable verbose output
- `--output, -o`: Output format (table, json, yaml)

### Tenant Management

#### List Tenants

```bash
guard-cli tenant list
```

#### Create Tenant

```bash
guard-cli tenant create "My Company"
```

#### Get Tenant Details

```bash
guard-cli tenant get tenant-id-here
```

#### Delete Tenant

```bash
guard-cli tenant delete tenant-id-here
```

### User Management

#### List Users

```bash
guard-cli user list --tenant tenant-id
```

#### Create User

```bash
# Basic user creation
guard-cli user create user@example.com Password123! --tenant tenant-id

# With additional details and MFA
guard-cli user create user@example.com Password123! \
  --tenant tenant-id \
  --first-name "John" \
  --last-name "Doe" \
  --enable-mfa
```

#### Get User Details

```bash
guard-cli user get user-id --tenant tenant-id
```

#### Delete User

```bash
guard-cli user delete user-id --tenant tenant-id
```

### Settings Management

#### Get All Settings

```bash
guard-cli settings get --tenant tenant-id
```

#### Set Individual Setting

```bash
guard-cli settings set auth_access_token_ttl "30m" --tenant tenant-id
guard-cli settings set sso_provider "workos" --tenant tenant-id
```

### Health Monitoring

#### Check API Health

```bash
guard-cli health
```

### Configuration Management

#### Show Current Configuration

```bash
guard-cli config show
```

#### Reinitialize Configuration

```bash
guard-cli config init
```

## Output Formats

### Table Format (Default)

```bash
guard-cli tenant list
```

```
ID                                   NAME                 ACTIVE   CREATED
-------------------------------------------------------------------------------------
550e8400-e29b-41d4-a716-446655440000 Acme Corp           Yes      2024-01-15 10:30:00
550e8400-e29b-41d4-a716-446655440001 Beta Inc            Yes      2024-01-16 14:20:00

Total: 2 tenants
```

### JSON Format

```bash
guard-cli tenant list --output json
```

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Corp",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
]
```

## Examples

### Complete Tenant Setup

```bash
# 1. Create tenant
TENANT_ID=$(guard-cli tenant create "New Company" --output json | jq -r '.id')

# 2. Configure tenant settings
guard-cli settings set auth_access_token_ttl "15m" --tenant $TENANT_ID
guard-cli settings set auth_refresh_token_ttl "720h" --tenant $TENANT_ID
guard-cli settings set app_cors_allowed_origins "https://app.example.com" --tenant $TENANT_ID

# 3. Create admin user
guard-cli user create admin@example.com SecurePass123! \
  --tenant $TENANT_ID \
  --first-name "Admin" \
  --last-name "User" \
  --enable-mfa

# 4. Verify setup
guard-cli tenant get $TENANT_ID
guard-cli user list --tenant $TENANT_ID
```

### Batch User Creation

```bash
#!/bin/bash
TENANT_ID="your-tenant-id"

# Create multiple users
users=(
  "user1@example.com:John:Doe"
  "user2@example.com:Jane:Smith"
  "user3@example.com:Bob:Johnson"
)

for user_data in "${users[@]}"; do
  IFS=':' read -r email first last <<< "$user_data"
  echo "Creating user: $email"
  
  guard-cli user create "$email" "TempPass123!" \
    --tenant "$TENANT_ID" \
    --first-name "$first" \
    --last-name "$last"
done
```

### Settings Backup and Restore

```bash
#!/bin/bash
TENANT_ID="your-tenant-id"

# Backup settings
guard-cli settings get --tenant $TENANT_ID --output json > settings-backup.json

# Restore settings (would need additional scripting)
# This is a conceptual example - actual restore would require parsing JSON
```

### Health Monitoring Script

```bash
#!/bin/bash
# health-check.sh

echo "Checking Guard API health..."
if guard-cli health --output json | jq -e '.status == "healthy"' > /dev/null; then
  echo "✅ API is healthy"
  exit 0
else
  echo "❌ API health check failed"
  exit 1
fi
```

## Error Handling

The CLI provides detailed error messages and appropriate exit codes:

```bash
# Check exit code
guard-cli tenant get invalid-id
echo $?  # Will be non-zero on error

# Verbose output for debugging
guard-cli tenant list --verbose
```

## Security Considerations

### Token Management

- Store API tokens securely
- Use environment variables in CI/CD pipelines
- Rotate tokens regularly
- Never commit tokens to version control

### Access Control

- Use tenant-specific tokens when possible
- Implement least-privilege access
- Monitor CLI usage through API logs
- Use MFA for administrative operations

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Guard CLI
        run: |
          curl -L https://github.com/corvushold/guard/releases/latest/download/guard-cli-linux-amd64 -o guard-cli
          chmod +x guard-cli
          sudo mv guard-cli /usr/local/bin/
      
      - name: Configure Guard CLI
        env:
          GUARD_API_URL: ${{ secrets.GUARD_API_URL }}
          GUARD_API_TOKEN: ${{ secrets.GUARD_API_TOKEN }}
        run: |
          guard-cli health
      
      - name: Create deployment tenant
        env:
          GUARD_API_TOKEN: ${{ secrets.GUARD_API_TOKEN }}
        run: |
          guard-cli tenant create "Production-$(date +%Y%m%d)"
```

### Monitoring Script

```bash
#!/bin/bash
# monitor-tenants.sh

echo "Tenant Health Report - $(date)"
echo "================================"

# Get all tenants
tenants=$(guard-cli tenant list --output json | jq -r '.[].id')

for tenant_id in $tenants; do
  echo "Checking tenant: $tenant_id"
  
  # Check user count
  user_count=$(guard-cli user list --tenant $tenant_id --output json | jq length)
  echo "  Users: $user_count"
  
  # Check critical settings
  settings=$(guard-cli settings get --tenant $tenant_id --output json)
  sso_enabled=$(echo $settings | jq -r '.sso_provider // "none"')
  echo "  SSO: $sso_enabled"
  
  echo ""
done
```

## Troubleshooting

### Common Issues

#### Authentication Errors

```bash
# Verify token and API URL
guard-cli config show
guard-cli health --verbose
```

#### Connection Issues

```bash
# Test connectivity
curl -f $GUARD_API_URL/health

# Check DNS resolution
nslookup api.guard.example.com
```

#### Permission Errors

```bash
# Verify token permissions
guard-cli health --verbose
# Check API logs for authorization failures
```

### Debug Mode

```bash
# Enable verbose logging
guard-cli --verbose tenant list

# Check configuration
guard-cli config show
```

## Development

### Building from Source

```bash
git clone https://github.com/corvushold/guard.git
cd guard/cmd/guard-cli
go mod download
go build -o guard-cli .
```

### Running Tests

```bash
go test ./...
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

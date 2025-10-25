# SDK Integration Guide

This guide shows how to integrate Corvus Guard SDKs with newly onboarded tenants across different platforms and frameworks.

## Table of Contents

- [TypeScript/JavaScript SDK](#typescriptjavascript-sdk)
- [Go SDK](#go-sdk)
- [Rust SDK](#rust-sdk)
- [Framework-Specific Integration](#framework-specific-integration)
- [Authentication Flows](#authentication-flows)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## TypeScript/JavaScript SDK

### Installation

```bash
npm install @corvushold/guard-sdk
```

### Basic Setup

```typescript
import { GuardClient, WebLocalStorage } from '@corvushold/guard-sdk';

const client = new GuardClient({
  baseUrl: 'https://your-guard-api.com', // Your Guard API URL
  tenantId: 'your-tenant-id', // From tenant onboarding
  storage: new WebLocalStorage('myapp'), // Persists tokens in localStorage
});
```

### Environment-Specific Configurations

#### Node.js Server
```typescript
import { GuardClient, InMemoryStorage } from '@corvushold/guard-sdk';

const client = new GuardClient({
  baseUrl: process.env.GUARD_API_URL,
  tenantId: process.env.GUARD_TENANT_ID,
  storage: new InMemoryStorage(),
});
```

#### React Application
```typescript
// src/lib/guard.ts
import { GuardClient, WebLocalStorage } from '@corvushold/guard-sdk';

export const guardClient = new GuardClient({
  baseUrl: import.meta.env.VITE_GUARD_API_URL,
  tenantId: import.meta.env.VITE_GUARD_TENANT_ID,
  storage: new WebLocalStorage('myapp'),
});

// src/hooks/useAuth.ts
import { useState, useEffect } from 'react';
import { guardClient } from '../lib/guard';

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await guardClient.me();
      setUser(response.data);
    } catch (error) {
      // User not authenticated
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    const response = await guardClient.passwordLogin({
      email,
      password,
      tenant_id: import.meta.env.VITE_GUARD_TENANT_ID,
    });

    if (response.meta.status === 200) {
      await checkAuth();
      return { success: true };
    } else if (response.meta.status === 202) {
      return { 
        success: false, 
        mfaRequired: true, 
        challengeToken: response.data.challenge_token 
      };
    }
  };

  const logout = async () => {
    await guardClient.logout();
    setUser(null);
  };

  return { user, loading, login, logout, checkAuth };
}
```

#### Next.js Application
```typescript
// lib/guard.ts
import { GuardClient, WebLocalStorage } from '@corvushold/guard-sdk';

export const guardClient = new GuardClient({
  baseUrl: process.env.NEXT_PUBLIC_GUARD_API_URL!,
  tenantId: process.env.NEXT_PUBLIC_GUARD_TENANT_ID!,
  storage: typeof window !== 'undefined' 
    ? new WebLocalStorage('myapp') 
    : new (await import('@corvushold/guard-sdk')).InMemoryStorage(),
});

// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('guard-access-token')?.value;
  
  if (!token && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  return NextResponse.next();
}

// pages/api/auth/login.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { guardClient } from '../../../lib/guard';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password } = req.body;
    const response = await guardClient.passwordLogin({
      email,
      password,
      tenant_id: process.env.NEXT_PUBLIC_GUARD_TENANT_ID!,
    });

    if (response.meta.status === 200) {
      // Set secure HTTP-only cookie
      res.setHeader('Set-Cookie', [
        `guard-access-token=${response.data.access_token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900`,
        `guard-refresh-token=${response.data.refresh_token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`
      ]);
      
      return res.status(200).json({ success: true });
    } else if (response.meta.status === 202) {
      return res.status(202).json({ 
        mfaRequired: true, 
        challengeToken: response.data.challenge_token 
      });
    }
  } catch (error) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
}
```

#### React Native
```typescript
import { GuardClient, reactNativeStorageAdapter } from '@corvushold/guard-sdk';
import AsyncStorage from '@react-native-async-storage/async-storage';

const client = new GuardClient({
  baseUrl: 'https://your-guard-api.com',
  tenantId: 'your-tenant-id',
  storage: reactNativeStorageAdapter(AsyncStorage, 'myapp'),
});

// AuthContext.tsx
import React, { createContext, useContext, useEffect, useState } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const response = await client.me();
      setUser(response.data);
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    const response = await client.passwordLogin({
      email,
      password,
      tenant_id: 'your-tenant-id',
    });

    if (response.meta.status === 200) {
      await checkAuthStatus();
      return { success: true };
    }
    
    return { success: false, error: 'Login failed' };
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout: () => client.logout() }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
```

## Go SDK

### Installation

```bash
go get github.com/corvushold/guard/sdk/go
```

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/corvushold/guard/sdk/go"
)

func main() {
    client := guard.NewClient(&guard.Config{
        BaseURL:  "https://your-guard-api.com",
        TenantID: "your-tenant-id",
    })

    // Password login
    loginResp, err := client.PasswordLogin(context.Background(), &guard.PasswordLoginRequest{
        Email:    "user@example.com",
        Password: "password123",
        TenantID: "your-tenant-id",
    })
    if err != nil {
        log.Fatal(err)
    }

    if loginResp.AccessToken != "" {
        // Set token for subsequent requests
        client.SetAccessToken(loginResp.AccessToken)
        
        // Get current user
        user, err := client.Me(context.Background())
        if err != nil {
            log.Fatal(err)
        }
        
        log.Printf("Logged in as: %s", user.Email)
    }
}
```

### Web Server Integration

```go
package main

import (
    "context"
    "encoding/json"
    "net/http"
    "os"
    
    "github.com/corvushold/guard/sdk/go"
)

type Server struct {
    guardClient *guard.Client
}

func NewServer() *Server {
    return &Server{
        guardClient: guard.NewClient(&guard.Config{
            BaseURL:  os.Getenv("GUARD_API_URL"),
            TenantID: os.Getenv("GUARD_TENANT_ID"),
        }),
    }
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    loginResp, err := s.guardClient.PasswordLogin(r.Context(), &guard.PasswordLoginRequest{
        Email:    req.Email,
        Password: req.Password,
        TenantID: os.Getenv("GUARD_TENANT_ID"),
    })
    if err != nil {
        http.Error(w, "Login failed", http.StatusUnauthorized)
        return
    }

    // Set secure cookies
    http.SetCookie(w, &http.Cookie{
        Name:     "access_token",
        Value:    loginResp.AccessToken,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   900, // 15 minutes
    })

    json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("access_token")
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Verify token
        s.guardClient.SetAccessToken(cookie.Value)
        _, err = s.guardClient.Introspect(r.Context())
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        next(w, r)
    }
}
```

## Rust SDK

### Installation

```toml
[dependencies]
guard-sdk = { git = "https://github.com/corvushold/guard", path = "sdk/rust" }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use guard_sdk::{Client, Config, PasswordLoginRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(Config {
        base_url: "https://your-guard-api.com".to_string(),
        tenant_id: Some("your-tenant-id".to_string()),
    });

    // Password login
    let login_request = PasswordLoginRequest {
        email: "user@example.com".to_string(),
        password: "password123".to_string(),
        tenant_id: "your-tenant-id".to_string(),
    };

    let login_response = client.password_login(login_request).await?;
    
    if let Some(access_token) = login_response.access_token {
        // Set token for subsequent requests
        client.set_access_token(access_token);
        
        // Get current user
        let user = client.me().await?;
        println!("Logged in as: {}", user.email);
    }

    Ok(())
}
```

### Axum Web Server Integration

```rust
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use guard_sdk::{Client, Config, PasswordLoginRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    guard_client: Arc<Client>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mfa_required: Option<bool>,
}

async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let login_request = PasswordLoginRequest {
        email: payload.email,
        password: payload.password,
        tenant_id: std::env::var("GUARD_TENANT_ID").unwrap(),
    };

    match state.guard_client.password_login(login_request).await {
        Ok(response) => {
            if response.access_token.is_some() {
                Ok(Json(LoginResponse {
                    success: true,
                    mfa_required: None,
                }))
            } else {
                Ok(Json(LoginResponse {
                    success: false,
                    mfa_required: Some(true),
                }))
            }
        }
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

#[tokio::main]
async fn main() {
    let guard_client = Arc::new(Client::new(Config {
        base_url: std::env::var("GUARD_API_URL").unwrap(),
        tenant_id: Some(std::env::var("GUARD_TENANT_ID").unwrap()),
    }));

    let app_state = AppState { guard_client };

    let app = Router::new()
        .route("/api/auth/login", post(login_handler))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Authentication Flows

### Password Login with MFA

```typescript
import { GuardClient, isTokensResp, isMfaChallengeResp } from '@corvushold/guard-sdk';

async function authenticateUser(email: string, password: string, tenantId: string) {
  const client = new GuardClient({
    baseUrl: 'https://your-guard-api.com',
    tenantId,
  });

  try {
    const loginResponse = await client.passwordLogin({
      email,
      password,
      tenant_id: tenantId,
    });

    if (loginResponse.meta.status === 200 && isTokensResp(loginResponse.data)) {
      // Login successful - tokens are automatically stored
      console.log('Login successful');
      return { success: true, user: await client.me() };
    } 
    
    if (loginResponse.meta.status === 202 && isMfaChallengeResp(loginResponse.data)) {
      // MFA required
      console.log('MFA challenge required');
      return {
        success: false,
        mfaRequired: true,
        challengeToken: loginResponse.data.challenge_token,
        availableMethods: loginResponse.data.available_methods,
      };
    }
  } catch (error) {
    console.error('Login failed:', error);
    return { success: false, error: error.message };
  }
}

async function verifyMFA(challengeToken: string, code: string, method: string = 'totp') {
  const client = new GuardClient({
    baseUrl: 'https://your-guard-api.com',
  });

  try {
    const verifyResponse = await client.mfaVerify({
      challenge_token: challengeToken,
      method,
      code,
    });

    if (verifyResponse.meta.status === 200) {
      console.log('MFA verification successful');
      return { success: true, user: await client.me() };
    }
  } catch (error) {
    console.error('MFA verification failed:', error);
    return { success: false, error: error.message };
  }
}
```

### Magic Link Authentication

```typescript
async function sendMagicLink(email: string, tenantId: string, redirectUrl: string) {
  const client = new GuardClient({
    baseUrl: 'https://your-guard-api.com',
    tenantId,
  });

  try {
    await client.magicSend({
      tenant_id: tenantId,
      email,
      redirect_url: redirectUrl,
    });
    
    return { success: true, message: 'Magic link sent to email' };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function verifyMagicLink(token: string) {
  const client = new GuardClient({
    baseUrl: 'https://your-guard-api.com',
  });

  try {
    const verifyResponse = await client.magicVerify({ token });
    
    if (verifyResponse.meta.status === 200) {
      return { success: true, user: await client.me() };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}
```

### SSO Integration

```typescript
// Initiate SSO flow
function initiateSSO(tenantId: string, provider: string, redirectUri: string) {
  const ssoUrl = `https://your-guard-api.com/v1/auth/sso/${provider}/start?tenant_id=${tenantId}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  window.location.href = ssoUrl;
}

// Handle SSO callback
async function handleSSOCallback(code: string, state: string) {
  const client = new GuardClient({
    baseUrl: 'https://your-guard-api.com',
  });

  try {
    // The callback is handled automatically by Guard
    // Check if user is now authenticated
    const user = await client.me();
    return { success: true, user };
  } catch (error) {
    return { success: false, error: 'SSO authentication failed' };
  }
}
```

## Error Handling

### TypeScript SDK Error Handling

```typescript
import { GuardClient, ApiError, RateLimitError } from '@corvushold/guard-sdk';

async function handleGuardErrors() {
  const client = new GuardClient({
    baseUrl: 'https://your-guard-api.com',
    tenantId: 'your-tenant-id',
  });

  try {
    await client.passwordLogin({
      email: 'user@example.com',
      password: 'wrong-password',
      tenant_id: 'your-tenant-id',
    });
  } catch (error) {
    if (error instanceof RateLimitError) {
      console.log(`Rate limited. Retry after ${error.retryAfter} seconds`);
      console.log(`Next retry at: ${error.nextRetryAt}`);
      
      // Implement exponential backoff
      setTimeout(() => {
        // Retry the request
      }, error.retryAfter * 1000);
      
    } else if (error instanceof ApiError) {
      switch (error.status) {
        case 401:
          console.log('Invalid credentials');
          break;
        case 403:
          console.log('Access forbidden');
          break;
        case 404:
          console.log('Tenant not found');
          break;
        default:
          console.log(`API error: ${error.message}`);
      }
    } else {
      console.log('Network or other error:', error);
    }
  }
}
```

### Global Error Handler

```typescript
// React error boundary for Guard SDK errors
import React from 'react';
import { ApiError, RateLimitError } from '@corvushold/guard-sdk';

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class GuardErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    if (error instanceof RateLimitError) {
      // Handle rate limiting
      console.log('Rate limit exceeded, implementing backoff');
    } else if (error instanceof ApiError) {
      // Handle API errors
      if (error.status === 401) {
        // Redirect to login
        window.location.href = '/login';
      }
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-fallback">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message}</p>
          <button onClick={() => this.setState({ hasError: false })}>
            Try again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
```

## Best Practices

### 1. Token Management

```typescript
// Automatic token refresh
class GuardTokenManager {
  private client: GuardClient;
  private refreshTimer?: NodeJS.Timeout;

  constructor(client: GuardClient) {
    this.client = client;
    this.setupAutoRefresh();
  }

  private setupAutoRefresh() {
    // Refresh token 5 minutes before expiry
    const refreshInterval = (15 * 60 - 5 * 60) * 1000; // 10 minutes
    
    this.refreshTimer = setInterval(async () => {
      try {
        await this.client.refresh();
        console.log('Token refreshed successfully');
      } catch (error) {
        console.error('Token refresh failed:', error);
        // Redirect to login
        window.location.href = '/login';
      }
    }, refreshInterval);
  }

  destroy() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }
  }
}
```

### 2. Request Interceptors

```typescript
// Add request/response interceptors
class GuardClientWithInterceptors extends GuardClient {
  constructor(config: any) {
    super(config);
    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Add request ID for tracing
    this.addRequestInterceptor((config) => {
      config.headers = {
        ...config.headers,
        'X-Request-ID': crypto.randomUUID(),
      };
      return config;
    });

    // Handle common response patterns
    this.addResponseInterceptor(
      (response) => response,
      (error) => {
        if (error.status === 401) {
          // Clear stored tokens
          this.storage.clear();
          // Redirect to login
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }
}
```

### 3. Environment Configuration

```typescript
// config/guard.ts
interface GuardConfig {
  baseUrl: string;
  tenantId: string;
  environment: 'development' | 'staging' | 'production';
}

export const guardConfig: GuardConfig = {
  baseUrl: process.env.NEXT_PUBLIC_GUARD_API_URL || 'http://localhost:8080',
  tenantId: process.env.NEXT_PUBLIC_GUARD_TENANT_ID || '',
  environment: (process.env.NODE_ENV as any) || 'development',
};

// Validation
if (!guardConfig.baseUrl || !guardConfig.tenantId) {
  throw new Error('Guard configuration is incomplete. Check environment variables.');
}

export const createGuardClient = () => {
  return new GuardClient({
    baseUrl: guardConfig.baseUrl,
    tenantId: guardConfig.tenantId,
    storage: typeof window !== 'undefined' 
      ? new WebLocalStorage('myapp') 
      : new InMemoryStorage(),
  });
};
```

### 4. Testing

```typescript
// __tests__/auth.test.ts
import { GuardClient, InMemoryStorage } from '@corvushold/guard-sdk';

describe('Authentication', () => {
  let client: GuardClient;

  beforeEach(() => {
    client = new GuardClient({
      baseUrl: 'http://localhost:8080',
      tenantId: 'test-tenant-id',
      storage: new InMemoryStorage(),
    });
  });

  it('should login successfully with valid credentials', async () => {
    const response = await client.passwordLogin({
      email: 'test@example.com',
      password: 'TestPassword123!',
      tenant_id: 'test-tenant-id',
    });

    expect(response.meta.status).toBe(200);
    expect(response.data.access_token).toBeDefined();
  });

  it('should handle MFA challenge', async () => {
    const response = await client.passwordLogin({
      email: 'mfa-user@example.com',
      password: 'TestPassword123!',
      tenant_id: 'test-tenant-id',
    });

    expect(response.meta.status).toBe(202);
    expect(response.data.challenge_token).toBeDefined();
  });
});
```

This SDK integration guide provides comprehensive examples for integrating Corvus Guard with various platforms and frameworks, covering authentication flows, error handling, and best practices for production use.

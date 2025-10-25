import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  Users, 
  Settings, 
  Activity, 
  Shield, 
  Globe, 
  Mail, 
  Key,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowLeft
} from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import TenantSettingsPanel from './TenantSettingsPanel'

interface TenantInfo {
  id: string
  name: string
  is_active: boolean
  created_at: string
  updated_at: string
}

interface TenantStats {
  total_users: number
  active_users: number
  total_logins_today: number
  failed_logins_today: number
  mfa_enabled_users: number
  sso_configured: boolean
}

interface TenantDashboardProps {
  tenantId: string
  onBack?: () => void
}

export default function TenantDashboard({ tenantId, onBack }: TenantDashboardProps) {
  const { user } = useAuth()
  const { show: showToast } = useToast()
  const [loading, setLoading] = useState(true)
  const [tenantInfo, setTenantInfo] = useState<TenantInfo | null>(null)
  const [tenantStats, setTenantStats] = useState<TenantStats | null>(null)
  const [activeTab, setActiveTab] = useState('overview')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadTenantData()
  }, [tenantId])

  const loadTenantData = async () => {
    setLoading(true)
    setError(null)

    try {
      const client = getClient()
      const res = await client.getTenant(tenantId)
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to load tenant info')
      }
      setTenantInfo(res.data as any)

      // Load tenant statistics (mock data for now - would need actual endpoints)
      const mockStats: TenantStats = {
        total_users: Math.floor(Math.random() * 1000) + 10,
        active_users: Math.floor(Math.random() * 500) + 5,
        total_logins_today: Math.floor(Math.random() * 100) + 1,
        failed_logins_today: Math.floor(Math.random() * 10),
        mfa_enabled_users: Math.floor(Math.random() * 200) + 2,
        sso_configured: Math.random() > 0.5
      }
      setTenantStats(mockStats)

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load tenant data'
      setError(message)
      showToast({ description: message, variant: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getStatusBadge = (isActive: boolean) => {
    return (
      <Badge variant={isActive ? 'default' : 'secondary'} className="flex items-center gap-1">
        {isActive ? (
          <CheckCircle className="h-3 w-3" />
        ) : (
          <Clock className="h-3 w-3" />
        )}
        {isActive ? 'Active' : 'Inactive'}
      </Badge>
    )
  }

  const renderOverview = () => {
    if (!tenantInfo || !tenantStats) return null

    return (
      <div className="space-y-6" data-testid="tenant-overview">
        {/* Tenant Info Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <span data-testid="tenant-name">{tenantInfo.name}</span>
                  <span data-testid="tenant-status">{getStatusBadge(tenantInfo.is_active)}</span>
                </CardTitle>
                <CardDescription>
                  Tenant ID: <span data-testid="tenant-id">{tenantInfo.id}</span>
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="font-medium">Created:</span>
                <div className="text-muted-foreground">{formatDate(tenantInfo.created_at)}</div>
              </div>
              <div>
                <span className="font-medium">Last Updated:</span>
                <div className="text-muted-foreground">{formatDate(tenantInfo.updated_at)}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Users</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="total-users-stat">{tenantStats.total_users}</div>
              <p className="text-xs text-muted-foreground">
                {tenantStats.active_users} active
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Users</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="active-users-stat">{tenantStats.active_users}</div>
              <p className="text-xs text-muted-foreground">Currently active</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Logins Today</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="logins-today-stat">{tenantStats.total_logins_today}</div>
              <p className="text-xs text-muted-foreground">
                {tenantStats.failed_logins_today} failed
              </p>
            </CardContent>
          </Card>

          <Card data-testid="mfa-users-stat-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">MFA Users</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid="mfa-users-stat">{tenantStats.mfa_enabled_users}</div>
              <p className="text-xs text-muted-foreground">
                {Math.round((tenantStats.mfa_enabled_users / tenantStats.total_users) * 100)}% of users
              </p>
            </CardContent>
          </Card>

          <Card data-testid="sso-status-stat-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">SSO Status</CardTitle>
              <Key className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {tenantStats.sso_configured ? (
                  <CheckCircle className="h-8 w-8 text-green-500" />
                ) : (
                  <AlertTriangle className="h-8 w-8 text-yellow-500" />
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                {tenantStats.sso_configured ? 'Configured' : 'Not configured'}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Common tenant management tasks</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Button
                variant="outline"
                className="h-20 flex flex-col items-center gap-2"
                data-testid="quick-action-settings"
                onClick={() => setActiveTab('settings')}
              >
                <Settings className="h-6 w-6" />
                <span className="text-sm">Settings</span>
              </Button>
              
              <Button
                variant="outline"
                className="h-20 flex flex-col items-center gap-2"
                onClick={() => {
                  // Would navigate to users management
                  showToast({ description: 'User management coming soon', variant: 'info' })
                }}
              >
                <Users className="h-6 w-6" />
                <span className="text-sm">Manage Users</span>
              </Button>
              
              <Button
                variant="outline"
                className="h-20 flex flex-col items-center gap-2"
                onClick={() => {
                  // Would show audit logs
                  showToast({ description: 'Audit logs coming soon', variant: 'info' })
                }}
              >
                <Activity className="h-6 w-6" />
                <span className="text-sm">Audit Logs</span>
              </Button>
              
              <Button
                variant="outline"
                className="h-20 flex flex-col items-center gap-2"
                onClick={() => {
                  // Would show API keys/tokens
                  showToast({ description: 'API management coming soon', variant: 'info' })
                }}
              >
                <Key className="h-6 w-6" />
                <span className="text-sm">API Keys</span>
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Health Status */}
        <Card>
          <CardHeader>
            <CardTitle>Tenant Health</CardTitle>
            <CardDescription>Current status and configuration health</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <div>
                    <div className="font-medium">Tenant Active</div>
                    <div className="text-sm text-muted-foreground">Tenant is operational</div>
                  </div>
                </div>
                <Badge variant="default">Healthy</Badge>
              </div>

              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-3">
                  {tenantStats.sso_configured ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                  )}
                  <div>
                    <div className="font-medium">SSO Configuration</div>
                    <div className="text-sm text-muted-foreground">
                      {tenantStats.sso_configured ? 'SSO is configured' : 'SSO not configured'}
                    </div>
                  </div>
                </div>
                <Badge variant={tenantStats.sso_configured ? 'default' : 'secondary'}>
                  {tenantStats.sso_configured ? 'Configured' : 'Pending'}
                </Badge>
              </div>

              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <div>
                    <div className="font-medium">User Activity</div>
                    <div className="text-sm text-muted-foreground">
                      {tenantStats.total_logins_today} logins today
                    </div>
                  </div>
                </div>
                <Badge variant="default">Active</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-8">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
            Loading tenant dashboard...
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="py-8">
          <div className="text-center text-red-600">
            <AlertTriangle className="h-8 w-8 mx-auto mb-4" />
            <p>{error}</p>
            <Button onClick={loadTenantData} className="mt-4">
              Retry
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        {onBack && (
          <Button variant="ghost" size="sm" onClick={onBack}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
        )}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            {tenantInfo?.name || 'Tenant Dashboard'}
          </h1>
          <p className="text-muted-foreground">
            Manage and monitor tenant configuration and activity
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" data-testid="overview-tab">Overview</TabsTrigger>
          <TabsTrigger value="settings" data-testid="settings-tab">Settings</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {renderOverview()}
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          {tenantInfo && (
            <TenantSettingsPanel
              tenantId={tenantInfo.id}
              tenantName={tenantInfo.name}
              onSettingsUpdated={loadTenantData}
            />
          )}
        </TabsContent>

        <TabsContent value="users" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>User Management</CardTitle>
              <CardDescription>Manage users for this tenant</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>User management interface coming soon</p>
                <p className="text-sm">This will include user creation, role assignment, and MFA management</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="activity" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Activity & Audit Logs</CardTitle>
              <CardDescription>View tenant activity and audit trail</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Activity monitoring coming soon</p>
                <p className="text-sm">This will include login history, API usage, and security events</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

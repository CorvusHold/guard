import { createRoot } from 'react-dom/client'
import './global.css'
import App from '@/components/App'
import AdminSettings from '@/components/admin/Settings'
import TenantDashboard from '@/components/admin/tenants/TenantDashboard'
import TenantSettingsPanel from '@/components/admin/tenants/TenantSettingsPanel'
import TenantOnboardingWizard from '@/components/admin/tenants/TenantOnboardingWizard'
import TenantCreationPanel from '@/components/admin/tenants/TenantCreationPanel'
import SSOCallback from '@/components/auth/Callback'
import TenantCreate from '@/components/onboarding/TenantCreate'
import Signup from '@/components/onboarding/Signup'
import { AuthProvider, RequireAuth } from '@/lib/auth'
import { TenantProvider } from '@/lib/tenant'
import { ToastProvider } from '@/lib/toast'
import { ensureRuntimeConfigFromQuery } from '@/lib/runtime'

// Ensure runtime config from query params is persisted BEFORE React renders
ensureRuntimeConfigFromQuery()

const container = document.getElementById('root') as HTMLDivElement
const root = createRoot(container)

const path = window.location.pathname
let element: React.ReactNode = <App />
if (path.startsWith('/auth/callback')) {
  element = <SSOCallback />
} else if (path.startsWith('/tenant/create')) {
  element = <TenantCreate />
} else if (path.startsWith('/signup')) {
  element = <Signup />
} else if (path.startsWith('/admin')) {
  // Admin subroutes
  const mSettings = path.match(/^\/admin\/tenants\/([^/]+)\/settings$/)
  const mDashboard = path.match(/^\/admin\/tenants\/([^/]+)$/)
  if (mSettings) {
    const tid = decodeURIComponent(mSettings[1])
    element = (
      <RequireAuth>
        <div className="p-4">
          <TenantSettingsPanel tenantId={tid} tenantName={tid} />
        </div>
      </RequireAuth>
    )
  } else if (mDashboard) {
    const tid = decodeURIComponent(mDashboard[1])
    element = (
      <RequireAuth>
        <div className="p-4">
          <TenantDashboard tenantId={tid} />
        </div>
      </RequireAuth>
    )
  } else if (path === '/admin/tenants/create') {
    element = (
      <RequireAuth>
        <div className="p-4">
          <TenantCreationPanel />
        </div>
      </RequireAuth>
    )
  } else if (path === '/admin/tenants/onboard') {
    element = (
      <RequireAuth>
        <div className="p-4">
          <TenantOnboardingWizard />
        </div>
      </RequireAuth>
    )
  } else {
    element = (
      <RequireAuth>
        <AdminSettings />
      </RequireAuth>
    )
  }
}

root.render(
  <ToastProvider>
    <TenantProvider>
      <AuthProvider>{element}</AuthProvider>
    </TenantProvider>
  </ToastProvider>
)

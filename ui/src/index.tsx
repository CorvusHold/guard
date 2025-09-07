import { createRoot } from 'react-dom/client'
import './global.css'
import App from '@/components/App'
import SSOCallback from '@/components/auth/Callback'
import AdminSettings from '@/components/admin/Settings'
import { AuthProvider, RequireAuth } from '@/lib/auth'
import { TenantProvider } from '@/lib/tenant'

const container = document.getElementById('root') as HTMLDivElement
const root = createRoot(container)

const path = window.location.pathname
let element: React.ReactNode = <App />
if (path.startsWith('/auth/callback')) {
  element = <SSOCallback />
} else if (path.startsWith('/admin')) {
  element = (
    <RequireAuth>
      <AdminSettings />
    </RequireAuth>
  )
}

root.render(
  <TenantProvider>
    <AuthProvider>
      {element}
    </AuthProvider>
  </TenantProvider>
)

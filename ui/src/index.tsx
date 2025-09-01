import { createRoot } from 'react-dom/client'
import './global.css'
import App from '@/components/App'
import SSOCallback from '@/components/auth/Callback'
import AdminSettings from '@/components/admin/Settings'

const container = document.getElementById('root') as HTMLDivElement
const root = createRoot(container)

const path = window.location.pathname
let element: React.ReactNode = <App />
if (path.startsWith('/auth/callback')) {
  element = <SSOCallback />
} else if (path.startsWith('/admin')) {
  element = <AdminSettings />
}

root.render(element)

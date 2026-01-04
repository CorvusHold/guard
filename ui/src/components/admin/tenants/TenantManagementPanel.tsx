import { useState } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import TenantCreationPanel from './TenantCreationPanel'
import TenantListPanel from './TenantListPanel'

export default function TenantManagementPanel() {
  const [activeTab, setActiveTab] = useState<'list' | 'create'>('list')

  const handleTenantCreated = (tenantId: string, tenantName: string) => {
    // Switch to list tab after successful creation
    setActiveTab('list')
  }

  const handleTenantSelected = (tenantId: string, tenantName: string) => {
    // selection is handled upstream via useTenant
    setActiveTab('list')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Tenant Management</h2>
          <p className="text-muted-foreground">
            Create new tenants and manage existing ones
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as 'list' | 'create')}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="list">Tenant List</TabsTrigger>
          <TabsTrigger value="create">Create Tenant</TabsTrigger>
        </TabsList>
        
        <TabsContent value="list" className="space-y-4">
          <TenantListPanel onTenantSelected={handleTenantSelected} />
        </TabsContent>
        
        <TabsContent value="create" className="space-y-4">
          <TenantCreationPanel onTenantCreated={handleTenantCreated} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import { User } from 'lucide-react'

export default function ProfileSettings() {
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [loadingProfile, setLoadingProfile] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { show } = useToast()

  useEffect(() => {
    async function loadProfile() {
      try {
        const client = getClient()
        const res = await client.me()
        if (res.meta.status === 200 && res.data) {
          setFirstName(res.data.first_name || '')
          setLastName(res.data.last_name || '')
          setEmail(res.data.email || '')
        }
      } catch (err) {
        console.error('Failed to load profile:', err)
      } finally {
        setLoadingProfile(false)
      }
    }
    loadProfile()
  }, [])

  async function handleUpdateProfile(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const client = getClient()
      const res = await client.updateProfile({
        first_name: firstName.trim(),
        last_name: lastName.trim()
      })
      if (res.meta.status === 200) {
        show({ variant: 'success', title: 'Profile updated successfully' })
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to update profile'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to update profile', description: errMsg })
      }
    } catch (err: any) {
      const errMsg = err?.message || String(err)
      setError(errMsg)
      show({ variant: 'error', title: 'Error', description: errMsg })
    } finally {
      setLoading(false)
    }
  }

  if (loadingProfile) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-muted-foreground">Loading profile...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <User className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Profile Settings</h1>
      </div>

      <div className="rounded-xl border p-6">
        <h2 className="text-lg font-medium mb-4">Personal Information</h2>

        {error && (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="profile-error">
            {error}
          </div>
        )}

        <form onSubmit={handleUpdateProfile} className="space-y-4 max-w-md">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              value={email}
              disabled
              className="bg-muted"
            />
            <p className="text-xs text-muted-foreground">Email cannot be changed</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="first-name">First name</Label>
            <Input
              id="first-name"
              type="text"
              data-testid="first-name-input"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              placeholder="Enter your first name"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="last-name">Last name</Label>
            <Input
              id="last-name"
              type="text"
              data-testid="last-name-input"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              placeholder="Enter your last name"
            />
          </div>

          <Button
            type="submit"
            data-testid="update-profile-submit"
            disabled={loading}
          >
            {loading ? 'Saving...' : 'Save Changes'}
          </Button>
        </form>
      </div>
    </div>
  )
}

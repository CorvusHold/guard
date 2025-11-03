import { useEffect, useRef } from 'react'
import { getClient } from './sdk'
import { getRuntimeConfig } from './runtime'

/**
 * Hook to automatically refresh access tokens in bearer mode before they expire.
 *
 * In bearer mode, tokens are stored in localStorage and need to be refreshed
 * periodically. This hook sets up an interval to refresh tokens before expiry.
 *
 * Default: Refreshes every 14 minutes (before the typical 15min expiry)
 * Only active in bearer mode - cookie mode handles refresh server-side.
 */
export function useTokenRefresh(intervalMinutes: number = 14) {
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  useEffect(() => {
    const cfg = getRuntimeConfig()

    // Only refresh in bearer mode - cookie mode is handled server-side
    if (!cfg || cfg.auth_mode !== 'bearer') {
      return
    }

    const refreshTokens = async () => {
      try {
        const client = getClient()
        await client.refresh()
        console.log('[TokenRefresh] Tokens refreshed successfully')
      } catch (error: any) {
        // Silently fail - user will be prompted to login on next API call
        console.warn('[TokenRefresh] Failed to refresh tokens:', error?.message)
      }
    }

    // Initial refresh on mount (if tokens exist)
    refreshTokens()

    // Set up periodic refresh
    const intervalMs = intervalMinutes * 60 * 1000
    intervalRef.current = setInterval(refreshTokens, intervalMs)

    console.log(
      `[TokenRefresh] Auto-refresh enabled (every ${intervalMinutes} minutes)`
    )

    // Cleanup on unmount
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
        console.log('[TokenRefresh] Auto-refresh disabled')
      }
    }
  }, [intervalMinutes])
}

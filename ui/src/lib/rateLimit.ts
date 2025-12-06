import { isRateLimitError, type RateLimitError } from '../../../sdk/ts/src/errors'

export function formatRateLimitError(
  err: unknown,
  context?: string
): string | null {
  if (!isRateLimitError(err)) return null
  const e = err as RateLimitError

  const baseParts: string[] = ['Rate limit exceeded']
  if (context) {
    baseParts.push(context.trim().endsWith('.') ? context.trim() : `${context.trim()}.`)
  }
  let suffix = ' Please wait and try again.'

  if (typeof e.retryAfter === 'number' && e.retryAfter > 0) {
    const secs = e.retryAfter
    const plural = secs === 1 ? '' : 's'
    suffix = ` Please wait ${secs} second${plural} before trying again.`
  } else if (e.nextRetryAt instanceof Date && !Number.isNaN(e.nextRetryAt.getTime())) {
    const t = e.nextRetryAt.toLocaleTimeString()
    suffix = ` Please wait until ${t} before trying again.`
  }

  return `${baseParts.join(' ')}${suffix}`
}

import { isRateLimitError, type RateLimitError } from '../../../sdk/ts/src/errors'

export function formatRateLimitError(
  err: unknown,
  context?: string
): string | null {
  if (!isRateLimitError(err)) return null

  const baseParts: string[] = ['Rate limit exceeded']
  if (context) {
    baseParts.push(`${context.trim()}.`)
  }
  let suffix = ' Please wait and try again.'

  if (typeof err.retryAfter === 'number' && err.retryAfter > 0) {
    const secs = err.retryAfter
    const plural = secs === 1 ? '' : 's'
    suffix = ` Please wait ${secs} second${plural} before trying again.`
  } else if (err.nextRetryAt instanceof Date && !Number.isNaN(err.nextRetryAt.getTime())) {
    const t = err.nextRetryAt.toLocaleTimeString()
    suffix = ` Please wait until ${t} before trying again.`
  }

  return `${baseParts.join(' ')}${suffix}`
}

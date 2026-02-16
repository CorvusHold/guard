const encoder = new TextEncoder()

function base64UrlEncode(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function randomString(length = 64): string {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes).slice(0, length)
}

export async function createPKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = randomString(96)
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(codeVerifier))
  const codeChallenge = base64UrlEncode(new Uint8Array(digest))
  return { codeVerifier, codeChallenge }
}

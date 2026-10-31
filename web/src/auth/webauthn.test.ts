import { afterEach, describe, expect, it, vi } from 'vitest'
import { getWebAuthnAssertion } from './webauthn'

function installCredentials(credentials: unknown) {
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true })
}

const REQUEST_OPTIONS = {
  publicKey: {
    challenge: 'AQID-_8',
    rpId: 'dashboard.example.com',
    allowCredentials: [{ type: 'public-key' as const, id: 'Bw-_' }],
  },
}

describe('getWebAuthnAssertion', () => {
  afterEach(() => {
    Reflect.deleteProperty(navigator, 'credentials')
  })

  it('decodesBase64UrlFieldsAndSerialisesTheAssertion', async () => {
    const serializedAssertion = { id: 'credential-id', response: { signature: 'c2ln' } }
    const getCredential = vi.fn(async () => ({ toJSON: () => serializedAssertion }))
    installCredentials({ get: getCredential })

    const assertion = await getWebAuthnAssertion(REQUEST_OPTIONS)

    expect(assertion).toEqual(serializedAssertion)
    const requestArgument = (getCredential.mock.calls[0] as unknown as [CredentialRequestOptions])[0]
    const challengeBytes = new Uint8Array(requestArgument.publicKey?.challenge as ArrayBuffer)
    expect(Array.from(challengeBytes)).toEqual([1, 2, 3, 251, 255])
    const allowedId = new Uint8Array(requestArgument.publicKey?.allowCredentials?.[0].id as ArrayBuffer)
    expect(Array.from(allowedId)).toEqual([7, 15, 191])
    expect(requestArgument.publicKey?.rpId).toBe('dashboard.example.com')
  })

  it('translatesACancelledCeremonyIntoWebauthnFailed', async () => {
    installCredentials({ get: vi.fn(async () => Promise.reject(new DOMException('cancelled', 'NotAllowedError'))) })
    await expect(getWebAuthnAssertion(REQUEST_OPTIONS)).rejects.toMatchObject({ code: 'webauthn_failed' })
  })

  it('reportsAnUnsupportedBrowser', () => {
    expect(() => getWebAuthnAssertion(REQUEST_OPTIONS)).toThrowError(expect.objectContaining({ code: 'webauthn_unsupported' }))
  })

  it('reportsAnEmptyCredentialAsUnsupported', async () => {
    installCredentials({ get: vi.fn(async () => null) })
    await expect(getWebAuthnAssertion(REQUEST_OPTIONS)).rejects.toMatchObject({ code: 'webauthn_unsupported' })
  })
})

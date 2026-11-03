import { describe, expect, it } from 'vitest'
import { makeEngine } from '@/test/fixtures'
import { buildEngineInput, initialFormValues, isFormSubmittable, type EngineFormValues } from '@/lib/engineForm'

const PROXIED_ENGINE = makeEngine({
  name: 'remote-one',
  proxy: { kind: 'socks5', url: 'socks5://198.51.100.5:1080' },
  has_proxy_credentials: true,
})

function editedValues(changedFields: Partial<EngineFormValues>): EngineFormValues {
  return { ...initialFormValues(PROXIED_ENGINE), ...changedFields }
}

describe('engine form proxy credentials', () => {
  // The server keeps the stored username when only the password is sent for an
  // unchanged proxy destination: the form must not demand the username again.
  it('acceptsAProxyPasswordChangeAloneWhenTheDestinationIsUnchanged', () => {
    const valuesWithNewPassword = editedValues({ proxyPassword: 'new-proxy-password' })

    expect(isFormSubmittable(valuesWithNewPassword, PROXIED_ENGINE)).toBe(true)
    expect(buildEngineInput(valuesWithNewPassword, PROXIED_ENGINE).proxy).toEqual({
      kind: 'socks5',
      url: 'socks5://198.51.100.5:1080',
      password: 'new-proxy-password',
    })
  })

  it('stillRefusesAProxyPasswordAloneWhenTheDestinationChanges', () => {
    const valuesWithNewDestination = editedValues({ proxyUrl: 'socks5://198.51.100.6:1080', proxyPassword: 'new-proxy-password' })

    expect(isFormSubmittable(valuesWithNewDestination, PROXIED_ENGINE)).toBe(false)
  })

  it('stillRefusesAProxyPasswordAloneWhenNoCredentialIsStored', () => {
    const engineWithoutCredentials = { ...PROXIED_ENGINE, has_proxy_credentials: false }
    const valuesWithPasswordOnly = { ...initialFormValues(engineWithoutCredentials), proxyPassword: 'new-proxy-password' }

    expect(isFormSubmittable(valuesWithPasswordOnly, engineWithoutCredentials)).toBe(false)
  })

  it('stillRefusesAProxyUsernameWithoutItsPassword', () => {
    const valuesWithUsernameOnly = editedValues({ proxyUsername: 'proxy-user' })

    expect(isFormSubmittable(valuesWithUsernameOnly, PROXIED_ENGINE)).toBe(false)
  })
})

import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

describe('metrics page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('explainsThatPrometheusMustBeEnabledWhenMetricsAreUnavailable', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/metrics': { status: 200, body: { available: false, reason: 'unavailable' } },
    })
    renderApp('/metrics')

    expect(await screen.findByText(en.metrics.unavailable)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('rendersAcquisitionAndParsersTables', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      'GET /api/metrics': {
        status: 200,
        body: {
          available: true,
          acquisition: [{ source: 'file:/var/log/auth.log', lines_read: 636, parsed: 0, unparsed: 636 }],
          parsers: [{ name: 'crowdsecurity/syslog-logs', hits: 10, parsed: 9, unparsed: 1 }],
        },
      },
    })
    renderApp('/metrics')

    expect(await screen.findByText('file:/var/log/auth.log')).toBeInTheDocument()
    expect(screen.getByText('crowdsecurity/syslog-logs')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: en.metrics.acquisitionCaption })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: en.metrics.parsersCaption })).toBeInTheDocument()
  })
})

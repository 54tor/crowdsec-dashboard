import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { MALICIOUS_SCENARIO, makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const DECISIONS_URL = 'GET /api/decisions?page=1&per_page=20'

describe('decisions page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('listsDecisionsAndWarnsThatCommunityBlocklistIsExcluded', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [DECISIONS_URL]: { status: 200, body: makePage([makeDecision()]) },
    })
    renderApp('/decisions')

    expect(await screen.findByText('203.0.113.7', { selector: 'td bdi' })).toBeInTheDocument()
    expect(screen.getByText(en.decisions.communityNotice)).toBeInTheDocument()
  })

  it('showsTruncationNoticeWhenWindowMayBeTruncated', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [DECISIONS_URL]: { status: 200, body: makePage([makeDecision()], { window_size: 100, may_be_truncated: true }) },
    })
    renderApp('/decisions')

    expect(await screen.findByText('Only the most recent 100 entries are shown; older entries are not displayed.')).toBeInTheDocument()
  })

  it('rendersAttackerControlledValuesAsText', async () => {
    stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [DECISIONS_URL]: {
        status: 200,
        body: makePage([makeDecision({ scenario: MALICIOUS_SCENARIO, value: MALICIOUS_SCENARIO })]),
      },
    })
    const { container } = renderApp('/decisions')

    expect((await screen.findAllByText(MALICIOUS_SCENARIO)).length).toBeGreaterThan(0)
    expect(container.querySelector('img')).toBeNull()
  })
})

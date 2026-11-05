import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestedUrls, SESSION_OK, waitForDebounce } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

// Exact en.json value of filters.q.
const SEARCH_LABEL = 'Search'

const UNFILTERED_DECISIONS_URL = '/api/decisions?page=1&per_page=20'
const SEARCHED_DECISIONS_URL = '/api/decisions?page=1&per_page=20&q=198.51'

describe('decisions search', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('decisionsSendTheSearchTerm', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': SESSION_OK,
      [`GET ${UNFILTERED_DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision()]) },
      [`GET ${SEARCHED_DECISIONS_URL}`]: { status: 200, body: makePage([makeDecision({ value: '198.51.100.9' })]) },
    })
    renderApp('/decisions')
    await screen.findByText('203.0.113.7', { selector: 'td bdi' })

    await userEvent.type(screen.getByLabelText(SEARCH_LABEL), '198.51')
    await waitForDebounce()

    expect(await screen.findByText('198.51.100.9', { selector: 'td bdi' })).toBeInTheDocument()
    expect(requestedUrls(fetchMock)).toContain(SEARCHED_DECISIONS_URL)
  })
})

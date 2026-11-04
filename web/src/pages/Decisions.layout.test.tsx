import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const DECISIONS_URL = 'GET /api/decisions?page=1&per_page=20'
const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const TIME_WITH_SECONDS_PATTERN = /\d{1,2}:\d{2}:\d{2}/
const TIME_TO_THE_MINUTE_PATTERN = /\d{1,2}:\d{2}/

function stubDecisionsPage(decisionRows = [makeDecision()]) {
  return stubFetch({
    'GET /api/auth/me': SESSION_OK,
    [DECISIONS_URL]: { status: 200, body: makePage(decisionRows) },
  })
}

async function findFirstDecisionRow(): Promise<HTMLElement> {
  const table = await screen.findByRole('table', { name: en.decisions.caption })
  return within(table).getByText('203.0.113.7').closest('tr') as HTMLElement
}

describe('decisions page layout', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('simulatedDecisionUsesWarningBadge', async () => {
    stubDecisionsPage([makeDecision({ simulated: true })])
    renderApp('/decisions')

    const decisionRow = await findFirstDecisionRow()

    expect(within(decisionRow).getByText(en.decisions.columns.simulated)).toHaveAttribute('data-variant', 'warning')
  })

  it('valueAndScenarioAreMono', async () => {
    stubDecisionsPage()
    renderApp('/decisions')

    const decisionRow = await findFirstDecisionRow()

    expect(within(decisionRow).getByText('203.0.113.7').closest('td')).toHaveClass('font-mono')
    expect(within(decisionRow).getByText('crowdsecurity/ssh-bf').closest('td')).toHaveClass('font-mono')
  })

  it('expiryStopsAtTheMinute', async () => {
    stubDecisionsPage()
    renderApp('/decisions')

    const decisionRow = await findFirstDecisionRow()

    expect(decisionRow.textContent).toMatch(TIME_TO_THE_MINUTE_PATTERN)
    expect(decisionRow.textContent).not.toMatch(TIME_WITH_SECONDS_PATTERN)
  })

  it('decisionCardKeepsUnbanAction', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubDecisionsPage()
    renderApp('/decisions')

    const cardList = await screen.findByRole('list', { name: en.decisions.caption })
    const [decisionCard] = within(cardList).getAllByRole('listitem')

    expect(within(decisionCard).getByRole('button', { name: 'Unban 203.0.113.7' })).toBeInTheDocument()
  })

  it('banTriggerAndDensityInPageHeader', async () => {
    stubDecisionsPage()
    renderApp('/decisions')

    const pageTitle = await screen.findByRole('heading', { level: 1, name: en.decisions.title })
    const pageHeader = pageTitle.closest('header') as HTMLElement

    expect(await within(pageHeader).findByRole('button', { name: en.ban.open })).toBeInTheDocument()
    expect(within(pageHeader).getByRole('group', { name: en.list.density.label })).toBeInTheDocument()
  })

  it('banDialogConfirmIsPrimaryNotDestructive', async () => {
    stubDecisionsPage()
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: en.ban.open }))
    const banDialog = await screen.findByRole('dialog', { name: en.ban.title })

    expect(within(banDialog).getByRole('button', { name: en.ban.submit })).toHaveAttribute('data-variant', 'default')
  })

  it('showsTheDecisionsEmptyMessage', async () => {
    stubDecisionsPage([])
    renderApp('/decisions')

    expect(await screen.findByText(en.decisions.empty)).toBeInTheDocument()
  })
})

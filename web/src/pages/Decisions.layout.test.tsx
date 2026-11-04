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
const HOSTILE_VALUE_LENGTH = 300

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

  // A one-line value column must not let a 300-character value widen the whole
  // table: the value is cut to a bounded width, the full text stays in its title.
  it('longValueIsBoundedInTheTable', async () => {
    const hostileValue = 'a'.repeat(HOSTILE_VALUE_LENGTH)
    stubDecisionsPage([makeDecision({ value: hostileValue })])
    renderApp('/decisions')

    const table = await screen.findByRole('table', { name: en.decisions.caption })
    const boundedValue = within(table).getByText(hostileValue)

    expect(boundedValue).toHaveClass('inline-block', 'max-w-[40ch]', 'truncate')
    expect(boundedValue).toHaveAttribute('title', hostileValue)
  })

  // An IP stays on one line: it fits the bounded width, so nothing is cut.
  it('ipValueStaysOnOneLine', async () => {
    stubDecisionsPage()
    renderApp('/decisions')

    const decisionRow = await findFirstDecisionRow()
    const ipValue = within(decisionRow).getByText('203.0.113.7')

    expect(ipValue).toHaveClass('truncate')
    expect(ipValue.closest('td')).toHaveClass('whitespace-nowrap')
  })

  // Cards have room to wrap: there the bound and the cut are lifted.
  it('longValueWrapsInsideCard', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    const hostileValue = 'a'.repeat(HOSTILE_VALUE_LENGTH)
    stubDecisionsPage([makeDecision({ value: hostileValue })])
    renderApp('/decisions')

    const cardList = await screen.findByRole('list', { name: en.decisions.caption })
    const valueCell = within(cardList).getByText(hostileValue).parentElement

    expect(valueCell).toHaveClass(
      '[&_bdi[data-truncated]]:max-w-none',
      '[&_bdi[data-truncated]]:overflow-visible',
      '[&_bdi[data-truncated]]:whitespace-pre-wrap',
    )
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

  // The include-expired checkbox folds with the filters, so it counts as one.
  it('includeExpiredCountsAsAnActiveFilter', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubDecisionsPage()
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: en.filters.toggle }))
    await user.click(screen.getByLabelText(en.decisions.includeExpired))
    const filtersToggle = screen.getByRole('button', { name: /^Filters/ })
    await user.click(filtersToggle)

    expect(filtersToggle).toHaveAccessibleName(en.filters.toggleWithCount.replace('{{count}}', '1'))
  })

  it('densityToggleHiddenOnMobileCards', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubDecisionsPage()
    renderApp('/decisions')

    await screen.findByRole('list', { name: en.decisions.caption })

    expect(screen.queryByRole('group', { name: en.list.density.label })).toBeNull()
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

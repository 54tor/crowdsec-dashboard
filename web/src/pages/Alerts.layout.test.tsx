import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeAlert, makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const TIME_WITH_SECONDS_PATTERN = /\d{1,2}:\d{2}:\d{2}/
const TIME_TO_THE_MINUTE_PATTERN = /\d{1,2}:\d{2}/

function stubAlertsPage(alertRows = [makeAlert()]) {
  return stubFetch({
    'GET /api/auth/me': SESSION_OK,
    'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage(alertRows) },
    'GET /api/alerts?page=1&per_page=100': { status: 200, body: makePage(alertRows, { per_page: 100 }) },
  })
}

async function findFirstAlertRow(): Promise<HTMLElement> {
  const table = await screen.findByRole('table', { name: en.alerts.caption })
  return within(table).getByText('crowdsecurity/ssh-bf').closest('tr') as HTMLElement
}

describe('alerts page layout', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  // The status is computed in the browser from fields the list already carries:
  // an alert holding a decision is an active ban.
  it('statusColumnShowsBanActive', async () => {
    stubAlertsPage([makeAlert({ decisions: [makeDecision()] })])
    renderApp('/alerts')

    const alertRow = await findFirstAlertRow()

    expect(screen.getByRole('columnheader', { name: en.alerts.columns.status })).toBeInTheDocument()
    expect(within(alertRow).getByText(en.alerts.status.activeBan)).toBeInTheDocument()
  })

  it('machineSitsUnderEngine', async () => {
    stubAlertsPage()
    renderApp('/alerts')

    const alertRow = await findFirstAlertRow()

    expect(screen.queryByRole('columnheader', { name: 'Machine' })).toBeNull()
    const engineCell = within(alertRow).getByText('machine-one').closest('td') as HTMLElement
    expect(engineCell).toHaveTextContent('local')
  })

  it('datesStopAtTheMinute', async () => {
    stubAlertsPage()
    renderApp('/alerts')

    const alertRow = await findFirstAlertRow()

    expect(alertRow.textContent).toMatch(TIME_TO_THE_MINUTE_PATTERN)
    expect(alertRow.textContent).not.toMatch(TIME_WITH_SECONDS_PATTERN)
  })

  it('messageColumnIsWideOnly', async () => {
    stubAlertsPage()
    renderApp('/alerts')

    await findFirstAlertRow()

    expect(screen.getByRole('columnheader', { name: en.alerts.columns.message })).toHaveClass('hidden', 'min-[1680px]:table-cell')
  })

  // On a phone the five filter fields pushed the list below the fold: they
  // stay folded behind one button until the visitor asks for them.
  it('filtersFoldBehindButtonOnMobile', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubAlertsPage()
    const user = userEvent.setup()
    renderApp('/alerts')

    const filtersToggle = await screen.findByRole('button', { name: en.filters.toggle })

    expect(filtersToggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByLabelText(en.filters.scenario)).toBeNull()

    await user.click(filtersToggle)

    expect(filtersToggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByLabelText(en.filters.scenario)).toBeInTheDocument()
  })

  it('alertCardKeepsDeleteAction', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubAlertsPage([makeAlert({ id: 12 })])
    renderApp('/alerts')

    const cardList = await screen.findByRole('list', { name: en.alerts.caption })
    const [alertCard] = within(cardList).getAllByRole('listitem')

    expect(within(alertCard).getByRole('button', { name: 'Delete alert 12' })).toBeInTheDocument()
    expect(alertCard).not.toHaveTextContent(makeAlert().message)
  })

  it('densityToggleInPageHeader', async () => {
    stubAlertsPage()
    renderApp('/alerts')

    const pageTitle = await screen.findByRole('heading', { level: 1, name: en.alerts.title })
    const pageHeader = pageTitle.closest('header') as HTMLElement

    expect(within(pageHeader).getByRole('group', { name: en.list.density.label })).toBeInTheDocument()
  })
})

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
const DESKTOP_VIEWPORT_WIDTH_IN_PIXELS = 1920
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

  // Once folded, the panel no longer shows what narrows the list: the toggle
  // label carries the number of filters currently set.
  it('foldedFiltersToggleCountsActiveFilters', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubAlertsPage()
    const user = userEvent.setup()
    renderApp('/alerts')

    await user.click(await screen.findByRole('button', { name: en.filters.toggle }))
    await user.type(screen.getByLabelText(en.filters.scenario), 'crowdsecurity/ssh-bf')
    await user.type(screen.getByLabelText(en.filters.since), '24h')
    const filtersToggle = screen.getByRole('button', { name: /^Filters/ })
    await user.click(filtersToggle)

    const expectedToggleLabel = en.filters.toggleWithCount.replace('{{count}}', '2')
    expect(filtersToggle).toHaveAccessibleName(expectedToggleLabel)
    expect(filtersToggle).toHaveAttribute('aria-expanded', 'false')
  })

  // A folded panel would hide the message explaining why the list stopped
  // refreshing, so an invalid field keeps the panel open.
  it('filtersPanelStaysOpenWhileAFieldIsInvalid', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubAlertsPage()
    const user = userEvent.setup()
    renderApp('/alerts')

    await user.click(await screen.findByRole('button', { name: en.filters.toggle }))
    await user.type(screen.getByLabelText(en.filters.ip), 'not-an-ip')
    expect(await screen.findByText(en.filters.ipInvalid)).toBeInTheDocument()
    const filtersToggle = screen.getByRole('button', { name: /^Filters/ })
    await user.click(filtersToggle)

    expect(filtersToggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(en.filters.ipInvalid)).toBeInTheDocument()
  })

  // Cards ignore the row density, so the toggle would do nothing on a phone.
  it('densityToggleHiddenOnMobileCards', async () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    stubAlertsPage()
    renderApp('/alerts')

    await screen.findByRole('list', { name: en.alerts.caption })

    expect(screen.queryByRole('group', { name: en.list.density.label })).toBeNull()
  })

  it('filtersStayVisibleWithoutToggleOnDesktop', async () => {
    setViewportWidth(DESKTOP_VIEWPORT_WIDTH_IN_PIXELS)
    stubAlertsPage()
    renderApp('/alerts')

    await findFirstAlertRow()

    expect(screen.getByLabelText(en.filters.scenario)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.filters.toggle })).toBeNull()
  })

  // The segment hides its native radio, so the double focus ring (amber outline
  // plus inner dark halo) has to be drawn on the visible segment.
  it('originSegmentShowsTheDoubleFocusRing', async () => {
    stubAlertsPage()
    renderApp('/alerts')

    const appSecRadio = await screen.findByRole('radio', { name: en.filters.originAppSec })
    const visibleSegment = appSecRadio.nextElementSibling as HTMLElement

    expect(visibleSegment).toHaveClass('peer-focus-visible:outline-ring', 'peer-focus-visible:shadow-[0_0_0_2px_var(--focus-inner)]')
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

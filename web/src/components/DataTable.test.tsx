import { fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { DensityToggle } from '@/components/DensityToggle'
import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'
import en from '@/i18n/en.json'
import { TABLE_DENSITY_STORAGE_KEY } from '@/hooks/useTableDensity'
import { MALICIOUS_SCENARIO } from '@/test/fixtures'
import { setViewportWidth } from '@/test/matchMedia'
import { prepareEnglishApp } from '@/test/pageHarness'

interface SampleAlertRow {
  identifier: number
  scenario: string
  sourceAddress: string
  message: string
}

const PHONE_VIEWPORT_WIDTH_IN_PIXELS = 390
const LONG_UNTRUSTED_VALUE_LENGTH = 300

const SAMPLE_ROWS: SampleAlertRow[] = [
  { identifier: 1, scenario: 'crowdsecurity/ssh-bf', sourceAddress: '192.0.2.10', message: 'hidden message one' },
  { identifier: 2, scenario: 'crowdsecurity/http-probing', sourceAddress: '192.0.2.20', message: 'hidden message two' },
]

// Covers every mobile placement: primary title, secondary details, a column
// hidden from cards and an actions column that must survive in the card footer.
const SAMPLE_COLUMNS: DataTableColumn<SampleAlertRow>[] = [
  { key: 'scenario', header: 'Scenario', mobile: 'primary', className: 'font-mono', cell: (alertRow) => <UntrustedText value={alertRow.scenario} /> },
  { key: 'source', header: 'Source', cell: (alertRow) => alertRow.sourceAddress },
  { key: 'message', header: 'Message', mobile: 'hidden', visibleFrom: 'wide', cell: (alertRow) => alertRow.message },
  {
    key: 'actions',
    header: 'Actions',
    mobile: 'actions',
    cell: (alertRow) => <button type="button">{`Delete alert ${alertRow.identifier}`}</button>,
  },
]

function renderSampleTable(options: { cardsOnMobile?: boolean; rows?: SampleAlertRow[]; emptyMessage?: string } = {}) {
  return render(
    <>
      <DensityToggle />
      <DataTable
        caption="Sample alerts"
        columns={SAMPLE_COLUMNS}
        rows={options.rows ?? SAMPLE_ROWS}
        rowKey={(alertRow) => alertRow.identifier}
        cardsOnMobile={options.cardsOnMobile}
        emptyMessage={options.emptyMessage}
      />
    </>,
  )
}

function bodyRows(): HTMLElement[] {
  const [, ...rowsBelowTheHeader] = screen.getAllByRole('row')
  return rowsBelowTheHeader
}

function makeEveryStorageAccessThrow(): void {
  for (const storageMethodName of ['getItem', 'setItem'] as const) {
    vi.spyOn(Storage.prototype, storageMethodName).mockImplementation(() => {
      throw new Error('storage disabled')
    })
  }
}

describe('data table', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => {
    vi.restoreAllMocks()
  })

  // The audit found nested scroll containers (region div plus the shadcn wrapper):
  // keyboard users had to tab into two boxes and the sticky header never stuck.
  it('rendersASingleScrollRegion', () => {
    const { container } = renderSampleTable()

    expect(screen.getAllByRole('region')).toHaveLength(1)
    expect(container.querySelector('[data-slot=table-container]')).toBeNull()
  })

  it('headersUseCondensedFontAndStickyHead', () => {
    const { container } = renderSampleTable()

    const tableHead = container.querySelector('thead')
    expect(tableHead).toHaveClass('sticky', 'top-0', 'bg-secondary')
    const scenarioHeader = screen.getByRole('columnheader', { name: 'Scenario' })
    expect(scenarioHeader).toHaveClass('font-condensed', 'text-xs', 'uppercase', 'tracking-wide', 'text-muted-foreground')
  })

  it('densityDefaultsTo40AndPersistsCompact', () => {
    renderSampleTable()

    for (const comfortableRow of bodyRows()) {
      expect(comfortableRow).toHaveClass('h-10')
    }

    fireEvent.click(screen.getByRole('button', { name: en.list.density.compact }))

    for (const compactRow of bodyRows()) {
      expect(compactRow).toHaveClass('h-8')
      expect(compactRow).not.toHaveClass('h-10')
    }
    expect(screen.getByRole('button', { name: en.list.density.compact })).toHaveAttribute('aria-pressed', 'true')
    expect(localStorage.getItem('table-density')).toBe('compact')
  })

  // The density lives in one shared store: a page showing two toggles must
  // never let them disagree after one of them is used.
  it('twoDensityTogglesStayInSync', () => {
    render(
      <>
        <DensityToggle />
        <DensityToggle />
      </>,
    )
    const [firstCompactButton, secondCompactButton] = screen.getAllByRole('button', { name: en.list.density.compact })

    fireEvent.click(firstCompactButton)

    expect(firstCompactButton).toHaveAttribute('aria-pressed', 'true')
    expect(secondCompactButton).toHaveAttribute('aria-pressed', 'true')
  })

  it('densityIsRestoredFromStorageOnMount', () => {
    localStorage.setItem(TABLE_DENSITY_STORAGE_KEY, 'compact')

    renderSampleTable()

    for (const compactRow of bodyRows()) {
      expect(compactRow).toHaveClass('h-8')
    }
    expect(screen.getByRole('button', { name: en.list.density.compact })).toHaveAttribute('aria-pressed', 'true')
  })

  // Private browsing or a blocked site storage makes every access throw: the
  // table must still render at the default density and the toggle must still work.
  it('densityFallsBackWhenStorageThrows', () => {
    makeEveryStorageAccessThrow()

    renderSampleTable()

    for (const comfortableRow of bodyRows()) {
      expect(comfortableRow).toHaveClass('h-10')
    }

    fireEvent.click(screen.getByRole('button', { name: en.list.density.compact }))

    for (const compactRow of bodyRows()) {
      expect(compactRow).toHaveClass('h-8')
    }
  })

  // Compact used to change only the minimum row height, which multi-line rows
  // already exceed: the cell padding has to shrink too.
  it('compactDensityTightensCellPadding', () => {
    renderSampleTable()
    const sourceCell = screen.getByText('192.0.2.10').closest('td')
    expect(sourceCell).toHaveClass('py-1.5')

    fireEvent.click(screen.getByRole('button', { name: en.list.density.compact }))

    expect(sourceCell).toHaveClass('py-0.5')
    expect(sourceCell).not.toHaveClass('py-1.5')
  })

  // break-all split IPs and short words mid-value even when they fitted: the
  // value may only break where it would otherwise overflow.
  it('untrustedTextBreaksOnlyWhereItWouldOverflow', () => {
    render(<UntrustedText value="192.0.2.44" />)

    const untrustedValue = screen.getByText('192.0.2.44')
    expect(untrustedValue).toHaveClass('whitespace-pre-wrap', '[overflow-wrap:anywhere]')
    expect(untrustedValue).not.toHaveClass('break-all')
  })

  // A short-value column must keep its value on one line in a table (the scroll
  // region scrolls instead), but may still wrap inside a phone card.
  it('noWrapColumnStaysOnOneLineInTablesOnly', () => {
    const noWrapColumns: DataTableColumn<SampleAlertRow>[] = [
      { key: 'scenario', header: 'Scenario', mobile: 'primary', cell: (alertRow) => alertRow.scenario },
      { key: 'source', header: 'Source', noWrap: true, cell: (alertRow) => <UntrustedText value={alertRow.sourceAddress} /> },
    ]
    const noWrapTable = <DataTable caption="Sample alerts" columns={noWrapColumns} rows={SAMPLE_ROWS} rowKey={(alertRow) => alertRow.identifier} cardsOnMobile />

    const { rerender } = render(noWrapTable)
    const sourceCell = screen.getByText('192.0.2.10').closest('td')
    expect(sourceCell).toHaveClass('whitespace-nowrap', '[&_bdi]:whitespace-nowrap')
    expect(sourceCell).not.toHaveClass('whitespace-normal')

    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    rerender(noWrapTable)
    const sourceDetails = screen.getByText('192.0.2.10').closest('dd')
    expect(sourceDetails).not.toHaveClass('whitespace-nowrap')
    expect(sourceDetails).not.toHaveClass('[&_bdi]:whitespace-nowrap')
  })

  // A long status badge (« Aucun contact depuis plus de 5 minutes ») used to
  // overflow a 375 px card because badges never wrap.
  it('longBadgeWrapsInsideCard', () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    const longBadgeLabel = 'No contact for more than five minutes on this machine'
    const badgeColumns: DataTableColumn<SampleAlertRow>[] = [
      { key: 'scenario', header: 'Scenario', mobile: 'primary', cell: (alertRow) => alertRow.scenario },
      { key: 'status', header: 'Status', cell: () => <Badge variant="warning">{longBadgeLabel}</Badge> },
    ]

    render(<DataTable caption="Sample alerts" columns={badgeColumns} rows={SAMPLE_ROWS} rowKey={(alertRow) => alertRow.identifier} cardsOnMobile />)

    const statusDetails = screen.getAllByText(longBadgeLabel)[0].closest('dd')
    expect(statusDetails).toHaveClass(
      '[&_[data-slot=badge]]:h-auto',
      '[&_[data-slot=badge]]:max-w-full',
      '[&_[data-slot=badge]]:whitespace-normal',
      '[&_[data-slot=badge]]:text-left',
    )
  })

  // A column class used to replace the wrap classes, so mono cells overflowed (audit 10).
  it('columnClassNameKeepsWrapping', () => {
    renderSampleTable()

    const scenarioCell = screen.getByText('crowdsecurity/ssh-bf').closest('td')
    expect(scenarioCell).toHaveClass('font-mono', 'break-words')
  })

  it('wideOnlyColumnIsHiddenBelow1680', () => {
    renderSampleTable()

    const messageHeader = screen.getByRole('columnheader', { name: 'Message' })
    const messageCell = screen.getByText('hidden message one').closest('td')
    for (const wideOnlyElement of [messageHeader, messageCell]) {
      expect(wideOnlyElement).toHaveClass('hidden', 'min-[1680px]:table-cell')
    }
  })

  it('cardShowsEveryNonHiddenColumnAndActions', () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)

    const { container } = renderSampleTable({ cardsOnMobile: true })

    expect(container.querySelector('table')).toBeNull()
    const cardList = screen.getByRole('list', { name: 'Sample alerts' })
    // Safari VoiceOver drops the list semantics of a ul styled without bullets.
    expect(cardList).toHaveAttribute('role', 'list')
    const cards = within(cardList).getAllByRole('listitem')
    expect(cards).toHaveLength(SAMPLE_ROWS.length)
    cards.forEach((card, rowPosition) => {
      const expectedRow = SAMPLE_ROWS[rowPosition]
      expect(card).toHaveTextContent('Scenario')
      expect(card).toHaveTextContent(expectedRow.scenario)
      expect(card).toHaveTextContent('Source')
      expect(card).toHaveTextContent(expectedRow.sourceAddress)
      expect(within(card).getByRole('button', { name: `Delete alert ${expectedRow.identifier}` })).toBeInTheDocument()
      expect(card).not.toHaveTextContent(expectedRow.message)
    })
  })

  // A 300-character scenario without spaces must break inside its card instead
  // of pushing the page wider than the phone.
  it('longUntrustedValueWrapsInsideCard', () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    const longUntrustedValue = 'a'.repeat(LONG_UNTRUSTED_VALUE_LENGTH)
    const longValueColumns: DataTableColumn<SampleAlertRow>[] = [
      { key: 'scenario', header: 'Scenario', mobile: 'primary', cell: (alertRow) => alertRow.scenario },
      { key: 'source', header: 'Source', cell: () => <UntrustedText value={longUntrustedValue} /> },
    ]

    render(
      <DataTable caption="Sample alerts" columns={longValueColumns} rows={SAMPLE_ROWS} rowKey={(alertRow) => alertRow.identifier} cardsOnMobile />,
    )

    const longValueDetails = screen.getAllByText(longUntrustedValue)[0].closest('dd')
    expect(longValueDetails).toHaveClass('min-w-0', 'break-words')
  })

  it('hostileValueStaysTextInsideCard', () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)
    const hostileRows = [{ ...SAMPLE_ROWS[0], scenario: MALICIOUS_SCENARIO }]

    const { container } = renderSampleTable({ cardsOnMobile: true, rows: hostileRows })

    expect(screen.getByRole('list', { name: 'Sample alerts' })).toHaveTextContent(MALICIOUS_SCENARIO)
    expect(container.querySelector('img')).toBeNull()
  })

  it('smallTablesStayTablesOnMobile', () => {
    setViewportWidth(PHONE_VIEWPORT_WIDTH_IN_PIXELS)

    const { container } = renderSampleTable()

    expect(container.querySelector('table')).not.toBeNull()
    expect(screen.getAllByRole('region')).toHaveLength(1)
  })

  it('emptyRowsRenderEmptyState', () => {
    const { container } = renderSampleTable({ rows: [] })

    expect(container.querySelector('table')).toBeNull()
    expect(screen.getByText(en.list.empty)).toBeInTheDocument()
  })

  it('emptyRowsUseTheGivenEmptyMessage', () => {
    renderSampleTable({ rows: [], emptyMessage: 'No alert yet.' })

    expect(screen.getByText('No alert yet.')).toBeInTheDocument()
  })
})

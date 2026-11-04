import { fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { DensityToggle } from '@/components/DensityToggle'
import { UntrustedText } from '@/components/UntrustedText'
import en from '@/i18n/en.json'
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

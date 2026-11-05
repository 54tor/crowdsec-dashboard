import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { beforeEach, describe, expect, it } from 'vitest'
import { ClientFilterField } from '@/components/ClientFilterField'
import en from '@/i18n/en.json'
import { prepareEnglishApp } from '@/test/pageHarness'

const FIELD_LABEL = 'Filter the sample list'

// Holds the value like a real page does, so typing and clearing go through onChange.
function StatefulFilterField({ visibleCount, totalCount }: { visibleCount: number; totalCount: number }) {
  const [filterText, setFilterText] = useState('')
  return <ClientFilterField id="sample-filter" label={FIELD_LABEL} value={filterText} onChange={setFilterText} visibleCount={visibleCount} totalCount={totalCount} />
}

describe('ClientFilterField', () => {
  beforeEach(prepareEnglishApp)

  it('announcesTheVisibleCount', () => {
    render(<StatefulFilterField visibleCount={2} totalCount={5} />)

    const countStatus = screen.getByRole('status')
    expect(countStatus).toHaveTextContent('2 of 5')
    expect(countStatus).toHaveAttribute('aria-live', 'polite')
  })

  it('rendersALabelledSearchFieldWithoutAutocomplete', () => {
    render(<StatefulFilterField visibleCount={1} totalCount={1} />)

    const filterInput = screen.getByLabelText(FIELD_LABEL)
    expect(filterInput).toHaveAttribute('type', 'search')
    expect(filterInput).toHaveAttribute('autocomplete', 'off')
    expect(filterInput).toHaveAttribute('maxlength', '128')
  })

  it('clearButtonEmptiesTheFieldAndGivesFocusBack', async () => {
    const user = userEvent.setup()
    render(<StatefulFilterField visibleCount={1} totalCount={1} />)

    expect(screen.queryByRole('button', { name: en.clientFilter.clear })).toBeNull()
    await user.type(screen.getByLabelText(FIELD_LABEL), 'abc')
    await user.click(screen.getByRole('button', { name: en.clientFilter.clear }))

    const filterInput = screen.getByLabelText(FIELD_LABEL)
    expect(filterInput).toHaveValue('')
    expect(filterInput).toHaveFocus()
  })

  // An empty list has nothing to filter: the field would only add noise.
  it('isHiddenWhenTheListIsEmpty', () => {
    render(<StatefulFilterField visibleCount={0} totalCount={0} />)

    expect(screen.queryByLabelText(FIELD_LABEL)).toBeNull()
    expect(screen.queryByRole('status')).toBeNull()
  })
})

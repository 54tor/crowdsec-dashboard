import { useState } from 'react'
import { matchesSearchText } from '@/lib/searchText'

export function useClientFilter<Row>(rows: readonly Row[], searchableTextsOf: (row: Row) => readonly (string | null | undefined)[]) {
  const [filterText, setFilterText] = useState('')
  const visibleRows = rows.filter((row) => matchesSearchText(filterText, searchableTextsOf(row)))
  return { filterText, setFilterText, visibleRows }
}

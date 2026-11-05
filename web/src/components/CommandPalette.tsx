import { Command } from 'cmdk'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { useAuth } from '@/auth/useAuth'
import { PaletteResultGroups } from '@/components/PaletteResultGroups'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { isRecordSearchTermUsable, usePaletteResults, type PaletteResults } from '@/hooks/usePaletteResults'

interface CommandPaletteProps {
  isOpen: boolean
  onOpenChange: (isOpen: boolean) => void
  returnFocusElement: HTMLElement | null
}

function countResults(results: PaletteResults): number {
  return results.pages.length + results.engineNames.length + results.alerts.length + results.decisions.length
}

function PaletteStatus({ results, searchTerm }: { results: PaletteResults; searchTerm: string }) {
  const { t } = useTranslation()
  const needsLongerTerm = searchTerm !== '' && !isRecordSearchTermUsable(searchTerm)
  const hasNoResult = !results.isSearchingRecords && countResults(results) === 0
  return (
    <div role="status" className="grid gap-1 px-2 text-xs text-muted-foreground empty:hidden">
      {results.isSearchingRecords && <p>{t('palette.searching')}</p>}
      {hasNoResult && <p>{t('palette.noResult')}</p>}
      {needsLongerTerm && <p>{t('palette.typeMore')}</p>}
    </div>
  )
}

function PaletteSearch({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation()
  const { accountRole } = useAuth()
  const [searchText, setSearchText] = useState('')
  const results = usePaletteResults(searchText, accountRole)
  const searchTerm = searchText.trim()
  return (
    <Command shouldFilter={false} vimBindings={false} label={t('palette.inputLabel')} className="grid gap-2">
      <Command.Input
        value={searchText}
        onValueChange={setSearchText}
        placeholder={t('palette.inputLabel')}
        autoComplete="off"
        className="h-11 w-full rounded-md border bg-background px-3 text-base outline-none focus-ring sm:text-sm"
      />
      <PaletteStatus results={results} searchTerm={searchTerm} />
      <Command.List className="max-h-[min(60vh,24rem)] overflow-y-auto">
        <PaletteResultGroups results={results} searchTerm={searchTerm} onNavigate={onNavigate} />
      </Command.List>
    </Command>
  )
}

export function CommandPalette({ isOpen, onOpenChange, returnFocusElement }: CommandPaletteProps) {
  const { t } = useTranslation()
  const navigate = useNavigate()

  function navigateAndClose(path: string) {
    onOpenChange(false)
    void navigate(path)
  }

  function returnFocusToOpener(closeEvent: Event) {
    closeEvent.preventDefault()
    returnFocusElement?.focus()
  }

  return (
    <Dialog open={isOpen} onOpenChange={onOpenChange}>
      <DialogContent aria-describedby={undefined} onCloseAutoFocus={returnFocusToOpener} className="top-[15%] translate-y-0 sm:max-w-lg">
        <DialogTitle className="sr-only">{t('palette.open')}</DialogTitle>
        <PaletteSearch onNavigate={navigateAndClose} />
      </DialogContent>
    </Dialog>
  )
}

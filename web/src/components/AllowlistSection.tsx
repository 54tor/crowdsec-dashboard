import { useTranslation } from 'react-i18next'
import { deleteAllowlist } from '@/api/allowlistsApi'
import type { AllowlistMutation, AllowlistView } from '@/api/types'
import { AllowlistEntriesTable } from '@/components/AllowlistEntriesTable'
import { AllowlistEntryDialog } from '@/components/AllowlistEntryDialog'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { UntrustedText } from '@/components/UntrustedText'
import { Badge } from '@/components/ui/badge'

interface AllowlistSectionProps {
  engineName: string
  allowlist: AllowlistView
  isWritable: boolean
  onWritten: (mutation: AllowlistMutation) => void
}

function AllowlistActions({ engineName, allowlist, onWritten }: Omit<AllowlistSectionProps, 'isWritable'>) {
  const { t } = useTranslation()

  async function removeAllowlist(confirm: string) {
    const mutation = await deleteAllowlist(engineName, allowlist.name, confirm)
    onWritten(mutation)
    return mutation
  }

  return (
    <div className="flex flex-wrap gap-2">
      <AllowlistEntryDialog engineName={engineName} allowlistName={allowlist.name} onWritten={onWritten} />
      <RowDeleteAction
        buttonLabel={t('allowlists.delete')}
        ariaLabel={t('allowlists.deleteLabel', { name: allowlist.name })}
        title={t('allowlists.deleteTitle')}
        description={t('allowlists.deleteDescription')}
        target={allowlist.name}
        request={removeAllowlist}
        invalidates={[]}
      />
    </div>
  )
}

export function AllowlistSection({ engineName, allowlist, isWritable, onWritten }: AllowlistSectionProps) {
  const { t } = useTranslation()
  return (
    <section className="space-y-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold">
              <UntrustedText value={allowlist.name} />
            </h2>
            {allowlist.console_managed && <Badge variant="secondary">{t('allowlists.consoleManaged')}</Badge>}
          </div>
          <p className="text-sm text-muted-foreground">
            <UntrustedText value={allowlist.description} />
          </p>
        </div>
        {isWritable && <AllowlistActions engineName={engineName} allowlist={allowlist} onWritten={onWritten} />}
      </div>
      <AllowlistEntriesTable engineName={engineName} allowlistName={allowlist.name} entries={allowlist.entries} isWritable={isWritable} onWritten={onWritten} />
    </section>
  )
}

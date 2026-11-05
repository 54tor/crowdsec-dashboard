import { Command } from 'cmdk'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { Alert, Decision } from '@/api/types'
import { Icon } from '@/components/Icon'
import { UntrustedText } from '@/components/UntrustedText'
import type { PaletteResults } from '@/hooks/usePaletteResults'
import { alertsSearchPath, decisionsSearchPath, engineAlertsPath } from '@/lib/paletteTargets'

const GROUP_CLASS_NAME =
  '[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pt-3 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:font-condensed [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-heading]]:uppercase'

const ITEM_CLASS_NAME =
  'flex min-h-10 cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm max-md:min-h-11 data-[selected=true]:bg-secondary'

interface PaletteResultGroupsProps {
  results: PaletteResults
  onNavigate: (path: string) => void
}

function PaletteItem({ value, onSelect, children }: { value: string; onSelect: () => void; children: ReactNode }) {
  return (
    <Command.Item value={value} onSelect={onSelect} className={ITEM_CLASS_NAME}>
      {children}
    </Command.Item>
  )
}

function AlertOptionText({ alert }: { alert: Alert }) {
  return (
    <span className="min-w-0">
      <UntrustedText value={alert.scenario} /> <UntrustedText value={alert.source.value} />
    </span>
  )
}

function DecisionOptionText({ decision }: { decision: Decision }) {
  return (
    <span className="min-w-0">
      <UntrustedText value={decision.value} /> <UntrustedText value={decision.type} /> <UntrustedText value={decision.scenario} />
    </span>
  )
}

export function PaletteResultGroups({ results, onNavigate }: PaletteResultGroupsProps) {
  const { t } = useTranslation()
  return (
    <>
      {results.pages.length > 0 && (
        <Command.Group heading={t('palette.pages')} className={GROUP_CLASS_NAME}>
          {results.pages.map((navItem) => (
            <PaletteItem key={navItem.path} value={`page:${navItem.path}`} onSelect={() => onNavigate(navItem.path)}>
              <Icon name={navItem.icon} className="size-4" />
              {t(navItem.labelKey)}
            </PaletteItem>
          ))}
        </Command.Group>
      )}
      {results.engineNames.length > 0 && (
        <Command.Group heading={t('palette.engines')} className={GROUP_CLASS_NAME}>
          {results.engineNames.map((engineName) => (
            <PaletteItem key={engineName} value={`engine:${engineName}`} onSelect={() => onNavigate(engineAlertsPath(engineName))}>
              <UntrustedText value={engineName} />
            </PaletteItem>
          ))}
        </Command.Group>
      )}
      {results.alerts.length > 0 && (
        <Command.Group heading={t('palette.alerts')} className={GROUP_CLASS_NAME}>
          {results.alerts.map((alert, alertPosition) => (
            <PaletteItem key={alertPosition} value={`alert:${alertPosition}`} onSelect={() => onNavigate(alertsSearchPath(results.recordSearchTerm))}>
              <AlertOptionText alert={alert} />
            </PaletteItem>
          ))}
        </Command.Group>
      )}
      {results.decisions.length > 0 && (
        <Command.Group heading={t('palette.decisions')} className={GROUP_CLASS_NAME}>
          {results.decisions.map((decision, decisionPosition) => (
            <PaletteItem key={decisionPosition} value={`decision:${decisionPosition}`} onSelect={() => onNavigate(decisionsSearchPath(results.recordSearchTerm))}>
              <DecisionOptionText decision={decision} />
            </PaletteItem>
          ))}
        </Command.Group>
      )}
    </>
  )
}

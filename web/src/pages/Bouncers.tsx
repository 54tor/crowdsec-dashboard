import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import type { Bouncer } from '@/api/types'
import { createBouncer, deleteBouncer } from '@/api/writeApi'
import { CreateSecretDialog } from '@/components/CreateSecretDialog'
import { HealthPageSection } from '@/components/HealthPageSection'
import { BouncersTable } from '@/components/HealthTables'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { WriteOnly } from '@/components/WriteOnly'
import { useCanWrite } from '@/hooks/useCanWrite'
import { HEALTH_QUERY_KEY } from '@/hooks/useReadResources'

export function Bouncers() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const actions = useMemo(
    () => canWrite ? ({
      header: t('bouncers.actions'),
      cell: (bouncer: Bouncer) => (
        <RowDeleteAction
          buttonLabel={t('common.delete')}
          ariaLabel={t('bouncers.deleteAria', { name: bouncer.name })}
          title={t('bouncers.deleteTitle', { name: bouncer.name })}
          description={t('bouncers.deleteDescription', { name: bouncer.name })}
          target={bouncer.name}
          request={(confirm) => deleteBouncer(bouncer.name, confirm)}
          invalidates={[HEALTH_QUERY_KEY]}
        />
      ),
    }) : undefined,
    [t, canWrite],
  )
  const labels = {
    title: t('bouncers.addTitle'),
    description: t('bouncers.addDescription'),
    nameLabel: t('bouncers.nameLabel'),
    secretLabel: t('bouncers.secretLabel'),
  }
  return (
    <HealthPageSection
      titleKey="bouncers.title"
      degradedPart="bouncers"
      toolbar={
        <WriteOnly>
          <CreateSecretDialog
            triggerLabel={t('bouncers.add')}
            labels={labels}
            createSecret={async (name) => (await createBouncer(name)).key}
          />
        </WriteOnly>
      }
    >
      {(report, now) => <BouncersTable bouncers={report.bouncers} now={now} actions={actions} />}
    </HealthPageSection>
  )
}

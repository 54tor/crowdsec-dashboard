import { useTranslation } from 'react-i18next'

export function EngineTargetNote({ engineName }: { engineName: string }) {
  const { t } = useTranslation()
  return (
    <p className="text-sm">
      {t('engineTarget.note')} <bdi className="font-mono font-medium">{engineName}</bdi>
    </p>
  )
}

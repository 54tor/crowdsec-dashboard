import { useTranslation } from 'react-i18next'
import { EmptyState } from '@/components/EmptyState'
import { Button } from '@/components/ui/button'

interface ConfigFileNavProps {
  files: string[]
  selectedFile: string | null
  onSelect: (fileName: string) => void
}

export function ConfigFileNav({ files, selectedFile, onSelect }: ConfigFileNavProps) {
  const { t } = useTranslation()
  return (
    <nav aria-label={t('config.files')}>
      {files.length === 0 ? (
        <EmptyState message={t('config.noFiles')} />
      ) : (
        <ul className="space-y-1">
          {files.map((fileName) => (
            <li key={fileName}>
              <Button
                variant={fileName === selectedFile ? 'outline' : 'ghost'}
                size="sm"
                aria-pressed={fileName === selectedFile}
                className="w-full justify-start font-mono break-all"
                onClick={() => onSelect(fileName)}
              >
                {fileName}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </nav>
  )
}

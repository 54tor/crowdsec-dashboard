import { useCallback, useState } from 'react'

interface FileSelection {
  engineName: string
  fileName: string
}

interface PendingChange {
  apply: () => void
}

export function useGuardedConfigSelection(engineName: string, changeEngine: (engineName: string) => void) {
  const [fileSelection, setFileSelection] = useState<FileSelection | null>(null)
  const [hasUnsavedEdits, setHasUnsavedEdits] = useState(false)
  const [pendingChange, setPendingChange] = useState<PendingChange | null>(null)
  const selectedFile = fileSelection?.engineName === engineName ? fileSelection.fileName : null

  const requestChange = useCallback(
    (apply: () => void) => {
      if (hasUnsavedEdits) {
        setPendingChange({ apply })
        return
      }
      apply()
    },
    [hasUnsavedEdits],
  )

  return {
    selectedFile,
    guard: requestChange,
    selectFile: (fileName: string) => requestChange(() => setFileSelection({ engineName, fileName })),
    selectEngine: (nextEngineName: string) => requestChange(() => changeEngine(nextEngineName)),
    clearSelection: () => setFileSelection(null),
    setHasUnsavedEdits,
    isDiscardPending: pendingChange !== null,
    cancelPendingChange: () => setPendingChange(null),
    applyPendingChange: () => {
      pendingChange?.apply()
      setPendingChange(null)
      setHasUnsavedEdits(false)
    },
  }
}

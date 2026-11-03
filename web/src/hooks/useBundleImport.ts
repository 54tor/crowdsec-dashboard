import { useState } from 'react'
import { applyImport, previewImport, type ApplyResponse, type BundleSection, type ImportPlan, type ParsedBundle } from '@/api/bundleApi'
import { ApiError } from '@/api/client'
import { readBundleFile } from '@/lib/bundleFile'

type Phase = 'idle' | 'previewing' | 'applying'

const PLAN_INVALIDATING_CODES = ['import_conflict', 'import_timeout']

export function useBundleImport() {
  const [bundle, setBundle] = useState<ParsedBundle | null>(null)
  const [availableSections, setAvailableSections] = useState<BundleSection[]>([])
  const [selectedSections, setSelectedSections] = useState<BundleSection[]>([])
  const [plan, setPlan] = useState<ImportPlan | null>(null)
  const [plannedSections, setPlannedSections] = useState<BundleSection[]>([])
  const [applyResponse, setApplyResponse] = useState<ApplyResponse | null>(null)
  const [phase, setPhase] = useState<Phase>('idle')
  const [failure, setFailure] = useState<unknown>(null)
  const [fileErrorCode, setFileErrorCode] = useState<string | null>(null)

  function reset() {
    setBundle(null)
    setAvailableSections([])
    setSelectedSections([])
    setPlan(null)
    setApplyResponse(null)
    setFailure(null)
    setFileErrorCode(null)
  }

  async function loadFile(file: File) {
    reset()
    const result = await readBundleFile(file)
    if ('errorCode' in result) {
      setFileErrorCode(result.errorCode)
      return
    }
    setBundle(result.bundle)
    setAvailableSections(result.availableSections)
    setSelectedSections(result.availableSections)
  }

  function toggleSection(sectionName: BundleSection) {
    setPlan(null)
    setApplyResponse(null)
    setSelectedSections((previous) => (previous.includes(sectionName) ? previous.filter((name) => name !== sectionName) : [...previous, sectionName]))
  }

  async function preview() {
    if (bundle === null || phase !== 'idle') {
      return
    }
    setPhase('previewing')
    setFailure(null)
    setApplyResponse(null)
    try {
      setPlan(await previewImport(bundle, selectedSections))
      setPlannedSections(selectedSections)
    } catch (previewFailure) {
      setPlan(null)
      setFailure(previewFailure)
    } finally {
      setPhase('idle')
    }
  }

  async function apply() {
    if (bundle === null || plan === null || phase !== 'idle') {
      return
    }
    setPhase('applying')
    setFailure(null)
    try {
      setApplyResponse(await applyImport(bundle, plannedSections, plan.digest))
      setPlan(null)
    } catch (applyFailure) {
      setFailure(applyFailure)
      if (applyFailure instanceof ApiError && PLAN_INVALIDATING_CODES.includes(applyFailure.code)) {
        setPlan(null)
      }
    } finally {
      setPhase('idle')
    }
  }

  return { bundle, availableSections, selectedSections, plan, applyResponse, phase, failure, fileErrorCode, loadFile, toggleSection, preview, apply, reset }
}

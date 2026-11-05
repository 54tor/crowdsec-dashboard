import { useState } from 'react'
import { applyImport, previewImport, type ApplyResponse, type BundleSection, type ImportPlan, type ParsedBundle } from '@/api/bundleApi'
import { ApiError } from '@/api/client'
import { readBundleFile } from '@/lib/bundleFile'

type Phase = 'idle' | 'previewing' | 'applying'

const PLAN_INVALIDATING_CODES = ['import_conflict', 'import_timeout']

interface PreparedPlan {
  plan: ImportPlan
  sections: BundleSection[]
  engineName: string
}

interface ApplyResult {
  response: ApplyResponse
  engineName: string
}

interface TaggedFailure {
  failure: unknown
  engineName: string
}

export function useBundleImport(engineName: string) {
  const [bundle, setBundle] = useState<ParsedBundle | null>(null)
  const [availableSections, setAvailableSections] = useState<BundleSection[]>([])
  const [selectedSections, setSelectedSections] = useState<BundleSection[]>([])
  const [preparedPlan, setPreparedPlan] = useState<PreparedPlan | null>(null)
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null)
  const [phase, setPhase] = useState<Phase>('idle')
  const [taggedFailure, setTaggedFailure] = useState<TaggedFailure | null>(null)
  const [fileErrorCode, setFileErrorCode] = useState<string | null>(null)

  const currentPlan = preparedPlan !== null && preparedPlan.engineName === engineName ? preparedPlan : null
  const currentFailure = taggedFailure !== null && taggedFailure.engineName === engineName ? taggedFailure.failure : null
  const currentApplyResult = applyResult !== null && applyResult.engineName === engineName ? applyResult : null

  function discardPlan() {
    setPreparedPlan(null)
    setApplyResult(null)
    setTaggedFailure(null)
  }

  function reset() {
    discardPlan()
    setBundle(null)
    setAvailableSections([])
    setSelectedSections([])
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
    setPreparedPlan(null)
    setApplyResult(null)
    setSelectedSections((previous) => (previous.includes(sectionName) ? previous.filter((name) => name !== sectionName) : [...previous, sectionName]))
  }

  async function preview() {
    if (bundle === null || phase !== 'idle') {
      return
    }
    const previewEngineName = engineName
    const previewSections = selectedSections
    setPhase('previewing')
    setTaggedFailure(null)
    setApplyResult(null)
    try {
      const plan = await previewImport(bundle, previewSections, previewEngineName)
      setPreparedPlan({ plan, sections: previewSections, engineName: previewEngineName })
    } catch (previewFailure) {
      setPreparedPlan(null)
      setTaggedFailure({ failure: previewFailure, engineName: previewEngineName })
    } finally {
      setPhase('idle')
    }
  }

  async function apply() {
    if (bundle === null || currentPlan === null || phase !== 'idle') {
      return
    }
    const { plan, sections, engineName: planEngineName } = currentPlan
    setPhase('applying')
    setTaggedFailure(null)
    try {
      const response = await applyImport(bundle, sections, plan.digest, planEngineName)
      setApplyResult({ response, engineName: planEngineName })
      setPreparedPlan(null)
    } catch (applyFailure) {
      setTaggedFailure({ failure: applyFailure, engineName: planEngineName })
      if (applyFailure instanceof ApiError && PLAN_INVALIDATING_CODES.includes(applyFailure.code)) {
        setPreparedPlan(null)
      }
    } finally {
      setPhase('idle')
    }
  }

  return {
    bundle,
    availableSections,
    selectedSections,
    plan: currentPlan?.plan ?? null,
    applyResponse: currentApplyResult?.response ?? null,
    phase,
    failure: currentFailure,
    fileErrorCode,
    loadFile,
    toggleSection,
    preview,
    apply,
    reset,
    discardPlan,
  }
}

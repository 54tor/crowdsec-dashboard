import { BUNDLE_SECTIONS, MAX_BUNDLE_BYTES, type BundleSection, type ParsedBundle } from '@/api/bundleApi'

export type BundleFileResult = { bundle: ParsedBundle; availableSections: BundleSection[] } | { errorCode: 'bundle_file_too_large' | 'bundle_file_invalid' }

export async function readBundleFile(file: File): Promise<BundleFileResult> {
  if (file.size > MAX_BUNDLE_BYTES) {
    return { errorCode: 'bundle_file_too_large' }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(await file.text())
  } catch {
    return { errorCode: 'bundle_file_invalid' }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { errorCode: 'bundle_file_invalid' }
  }
  const bundle = parsed as ParsedBundle
  const containedSections = typeof bundle.sections === 'object' && bundle.sections !== null ? bundle.sections : {}
  const availableSections = BUNDLE_SECTIONS.filter((sectionName) => sectionName in containedSections)
  return { bundle, availableSections }
}

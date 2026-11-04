export function hintIdFor(fieldId: string): string {
  return `${fieldId}-hint`
}

export function errorIdFor(fieldId: string): string {
  return `${fieldId}-error`
}

export function describedByIds(fieldId: string, hint?: string, error?: string | null): string | undefined {
  const descriptionIds: string[] = []
  if (hint) {
    descriptionIds.push(hintIdFor(fieldId))
  }
  if (error) {
    descriptionIds.push(errorIdFor(fieldId))
  }
  return descriptionIds.length > 0 ? descriptionIds.join(' ') : undefined
}

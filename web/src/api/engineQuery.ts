export const LOCAL_ENGINE_NAME = 'local'

export function isLocalEngine(engine?: string): boolean {
  return engine === undefined || engine === '' || engine === LOCAL_ENGINE_NAME
}

export function withEngine(path: string, engine?: string): string {
  if (isLocalEngine(engine)) {
    return path
  }
  const separator = path.includes('?') ? '&' : '?'
  return `${path}${separator}engine=${encodeURIComponent(engine as string)}`
}

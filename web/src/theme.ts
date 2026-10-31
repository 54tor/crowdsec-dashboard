export function followSystemColorScheme(): void {
  const darkSchemeQuery = window.matchMedia('(prefers-color-scheme: dark)')
  const applyScheme = () => document.documentElement.classList.toggle('dark', darkSchemeQuery.matches)
  applyScheme()
  darkSchemeQuery.addEventListener('change', applyScheme)
}

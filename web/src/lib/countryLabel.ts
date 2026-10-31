export function countryLabel(countryCode: string, language: string): string {
  try {
    const regionName = new Intl.DisplayNames([language], { type: 'region' }).of(countryCode)
    return regionName && regionName !== countryCode ? `${regionName} (${countryCode})` : countryCode
  } catch {
    return countryCode
  }
}

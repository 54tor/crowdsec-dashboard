import type { EngineInput, EngineProxyInput, EngineView } from '@/api/types'

export type ProxyKindChoice = '' | 'socks5' | 'http'

export interface EngineFormValues {
  name: string
  lapiUrl: string
  machineId: string
  machinePassword: string
  proxyKind: ProxyKindChoice
  proxyUrl: string
  proxyUsername: string
  proxyPassword: string
  clearProxyCredentials: boolean
  allowInsecureHttp: boolean
  publicAddresses: string
  enabled: boolean
  syncEnabled: boolean
}

export interface RequiredSecrets {
  machinePassword: boolean
  proxyCredentials: boolean
}

export function initialFormValues(engine?: EngineView): EngineFormValues {
  return {
    name: engine?.name ?? '',
    lapiUrl: engine?.lapi_url ?? '',
    machineId: engine?.machine_id ?? '',
    machinePassword: '',
    proxyKind: engine?.proxy?.kind ?? '',
    proxyUrl: engine?.proxy?.url ?? '',
    proxyUsername: '',
    proxyPassword: '',
    clearProxyCredentials: false,
    allowInsecureHttp: engine?.allow_insecure_http ?? false,
    publicAddresses: (engine?.public_addresses ?? []).join(', '),
    enabled: engine?.enabled ?? true,
    syncEnabled: engine?.sync_enabled ?? false,
  }
}

function destinationOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).origin
  } catch {
    return rawUrl
  }
}

function parsePublicAddresses(rawAddresses: string): string[] {
  return rawAddresses.split(/[\s,]+/).filter((address) => address !== '')
}

function hasProxyDestinationChanged(values: EngineFormValues, engine: EngineView): boolean {
  return values.proxyKind !== (engine.proxy?.kind ?? '') || values.proxyUrl !== (engine.proxy?.url ?? '')
}

export function requiredSecrets(values: EngineFormValues, engine?: EngineView): RequiredSecrets {
  if (!engine) {
    return { machinePassword: true, proxyCredentials: false }
  }
  const isUrlChanged = destinationOf(values.lapiUrl) !== destinationOf(engine.lapi_url)
  const isProxyChanged = values.proxyKind !== '' && hasProxyDestinationChanged(values, engine)
  return {
    machinePassword: isUrlChanged,
    proxyCredentials: engine.has_proxy_credentials && isProxyChanged && !values.clearProxyCredentials,
  }
}

function hasBothProxyCredentials(values: EngineFormValues): boolean {
  return values.proxyUsername !== '' && values.proxyPassword !== ''
}

function hasOneProxyCredential(values: EngineFormValues): boolean {
  return (values.proxyUsername !== '') !== (values.proxyPassword !== '')
}

export function isFormSubmittable(values: EngineFormValues, engine?: EngineView): boolean {
  const required = requiredSecrets(values, engine)
  const hasRequiredFields = values.lapiUrl !== '' && values.machineId !== '' && (engine !== undefined || values.name !== '')
  const hasProxyFields = values.proxyKind === '' || values.proxyUrl !== ''
  const hasMachinePassword = !required.machinePassword || values.machinePassword !== ''
  const hasProxyCredentials = !required.proxyCredentials || hasBothProxyCredentials(values)
  return hasRequiredFields && hasProxyFields && hasMachinePassword && hasProxyCredentials && !hasOneProxyCredential(values)
}

function buildProxy(values: EngineFormValues, engine?: EngineView): EngineProxyInput | null | undefined {
  if (values.proxyKind === '') {
    return engine?.proxy ? null : undefined
  }
  const proxy: EngineProxyInput = { kind: values.proxyKind, url: values.proxyUrl }
  if (hasBothProxyCredentials(values)) {
    proxy.username = values.proxyUsername
    proxy.password = values.proxyPassword
  }
  if (engine && values.clearProxyCredentials) {
    proxy.clear_credentials = true
  }
  return proxy
}

export function buildEngineInput(values: EngineFormValues, engine?: EngineView): EngineInput {
  const input: EngineInput = {
    lapi_url: values.lapiUrl,
    machine_id: values.machineId,
    proxy: buildProxy(values, engine),
    allow_insecure_http: values.allowInsecureHttp,
    public_addresses: parsePublicAddresses(values.publicAddresses),
    enabled: values.enabled,
    sync_enabled: values.syncEnabled,
  }
  if (values.machinePassword !== '') {
    input.machine_password = values.machinePassword
  }
  if (!engine) {
    input.name = values.name
  }
  return input
}

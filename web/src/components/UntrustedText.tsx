export function UntrustedText({ value }: { value: string }) {
  return <bdi className="whitespace-pre-wrap break-all">{value}</bdi>
}

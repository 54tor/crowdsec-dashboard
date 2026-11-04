export function UntrustedText({ value }: { value: string }) {
  return <bdi className="whitespace-pre-wrap [overflow-wrap:anywhere]">{value}</bdi>
}

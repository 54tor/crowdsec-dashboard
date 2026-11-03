export function downloadBlob(blob: Blob, fileName: string): void {
  const objectUrl = URL.createObjectURL(blob)
  const downloadLink = document.createElement('a')
  downloadLink.href = objectUrl
  downloadLink.download = fileName
  document.body.append(downloadLink)
  try {
    downloadLink.click()
  } finally {
    downloadLink.remove()
    setTimeout(() => URL.revokeObjectURL(objectUrl), 0)
  }
}

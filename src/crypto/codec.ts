export function numberToUint32LE(input: number) {
  const buffer = new ArrayBuffer(4)
  const u32 = new Uint32Array(buffer)
  u32[0] = input
  return new Uint8Array(buffer)
}

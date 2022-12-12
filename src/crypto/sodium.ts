export async function initializeSodium() {
  const sodium = (await import('libsodium-wrappers')).default
  await sodium.ready
  return sodium
}

export type Sodium = Awaited<ReturnType<typeof initializeSodium>>

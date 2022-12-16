import { initializeSodium } from '../../crypto/sodium'
import { keygen } from '../../lib'
import type { KeygenCommandArgs } from '../args'

export async function generateKeyPair(seed: KeygenCommandArgs['seed']) {
  const sodium = await initializeSodium()
  return keygen(sodium, seed)
}

export async function keygenCommand(args: KeygenCommandArgs) {
  const keypair = await generateKeyPair(args.seed)
  if (args.compact) {
    console.info(keypair.privateKey)
  } else {
    console.info(`Run the following command in your terminal to use this private key:

export SCEAU_PRIVATE_KEY="${keypair.privateKey}"

Associated public key:
${keypair.publicKey}`)
  }
}

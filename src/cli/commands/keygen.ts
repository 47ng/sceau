import { initializeSodium } from '../../crypto/sodium'
import type { KeygenCommandArgs } from '../args'

export async function keygenCommand(args: KeygenCommandArgs) {
  const sodium = await initializeSodium()
  const keypair = args.seed
    ? sodium.crypto_sign_seed_keypair(sodium.from_hex(args.seed), 'hex')
    : sodium.crypto_sign_keypair('hex')
  console.log(`SCEAU_PRIVATE_KEY="${keypair.privateKey}"`)
  if (args.pub) {
    console.log(`SCEAU_PUBLIC_KEY="${keypair.publicKey}"`)
  }
}

import fs from 'node:fs/promises'
import { initializeSodium } from '../../crypto/sodium'
import { sign } from '../../lib'
import type { SignCommandArgs } from '../args'
import { env } from '../env'

export async function signCommand(args: SignCommandArgs) {
  const privateKey = args.privateKey ?? env.SCEAU_PRIVATE_KEY
  if (!privateKey) {
    console.error(
      'Missing private key. Pass it either via the --privateKey argument or the SCEAU_PRIVATE_KEY environment variable.'
    )
    process.exit(1)
  }
  const buildURL = args.build ?? env.SCEAU_BUILD_URL
  const sourceURL = args.source ?? env.SCEAU_SOURCE_URL
  const packageDir = args.packageDir ?? process.cwd()
  const sodium = await initializeSodium()
  const sceau = await sign(sodium, {
    timestamp: new Date(),
    packageDir,
    privateKey,
    buildURL,
    sourceURL,
    ignoreFiles: [args.file],
  })
  await fs.writeFile(args.file, JSON.stringify(sceau))
  if (!args.quiet) {
    console.log(JSON.stringify(sceau, null, 2))
  }
}

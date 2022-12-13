import chalk from 'chalk'
import fs from 'node:fs/promises'
import path from 'node:path'
import { initializeSodium } from '../../crypto/sodium'
import { sceauSchema, verify } from '../../lib'
import type { VerifyCommandArgs } from '../args'

export async function verifyCommand(args: VerifyCommandArgs) {
  const sodium = await initializeSodium()
  try {
    const packageDir = args.packageDir ?? process.cwd()
    const sceauFilePath = path.resolve(packageDir, args.file)
    await fs.stat(sceauFilePath).catch(error => {
      if (error.code === 'ENOENT') {
        const message = 'This package is not signed'
        if (args.strict) {
          throw new Error(chalk.red(message))
        }
        console.info(message)
        process.exit(0)
      }
      throw error
    })
    const sceauFileContent = await fs.readFile(sceauFilePath, {
      encoding: 'utf8',
    })
    const sceau = sceauSchema.parse(JSON.parse(sceauFileContent))
    if (args.publicKey && args.publicKey !== sceau.publicKey) {
      console.error(`${chalk.red(
        'The package was signed using a different private key than the one you are expecting.'
      )}

  Supplied public key: ${args.publicKey}
  Embedded public key: ${sceau.publicKey}`)
      process.exit(1)
    }
    const publicKey = args.publicKey ?? sceau.publicKey
    await verify(sodium, sceau, packageDir, sodium.from_hex(publicKey))
    console.info(`${chalk.green('✅ Signature verified')}
Source:     ${sceau.sourceURL}
Build:      ${sceau.buildURL}
Signed on:  ${sceau.timestamp}`)
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  }
}

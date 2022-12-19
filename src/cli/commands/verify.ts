import chalk from 'chalk'
import fs from 'node:fs/promises'
import path from 'node:path'
import { initializeSodium } from '../../crypto/sodium'
import { sceauSchema, verify } from '../../lib'
import type { VerifyCommandArgs } from '../args'
import { env } from '../env'

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
    const pinnedPublicKey = args.publicKey ?? env.SCEAU_PUBLIC_KEY
    if (pinnedPublicKey && pinnedPublicKey !== sceau.publicKey) {
      console.error(`${chalk.red(
        'The package was signed using a different private key than the one you are expecting.'
      )}

  Supplied public key: ${pinnedPublicKey}
  Embedded public key: ${sceau.publicKey}`)
      process.exit(1)
    }
    const publicKey = pinnedPublicKey ?? sceau.publicKey
    const result = await verify(
      sodium,
      sceau,
      packageDir,
      sodium.from_hex(publicKey)
    )
    if (result.outcome === 'failure') {
      const padding = Math.max(
        ...result.manifestErrors.map(e => e.entry.path.length)
      )
      throw new Error(
        `Signature: ${
          result.signatureVerified
            ? chalk.yellow(
                'verified (but the rest of the sceau did not verify, see below)'
              )
            : chalk.red('invalid')
        }
  ${result.manifestErrors
    .map(
      error =>
        `${chalk.bold(error.entry.path).padEnd(padding)} ${error.message}`
    )
    .join('\n  ')}`
      )
    }
    console.info(`${chalk.green('✅ Signature verified')}
Source:     ${result.sourceURL}
Build:      ${result.buildURL}
Signed on:  ${result.timestamp}`)
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  }
}

#!/usr/bin/env zx

import { z } from 'zod'
import 'zx/globals'
import { initializeSodium } from './crypto/sodium'
import { generate, hexStringSchema } from './lib'

const DEFAULT_URL = 'unknown://local'

const envSchema = z.object({
  SCEAU_PRIVATE_KEY: hexStringSchema(64).optional(),
  SCEAU_PUBLIC_KEY: hexStringSchema(32).optional(),
  // todo: Detect build & source URLs based on environment (GitHub Actions)
  SCEAU_BUILD_URL: z.string().url().optional().default(DEFAULT_URL),
  SCEAU_SOURCE_URL: z.string().url().optional().default(DEFAULT_URL),
})

const env = envSchema.parse(process.env)
const sodium = await initializeSodium()

if (argv._[0] === 'keygen') {
  if (argv.seed && !hexStringSchema(64).safeParse(argv.seed).success) {
    console.error(
      'Error: private key seed should be a 64 byte hex string (128 characters)'
    )
    process.exit(1)
  }
  const keypair = argv.seed
    ? sodium.crypto_sign_seed_keypair(sodium.from_hex(argv.seed), 'hex')
    : sodium.crypto_sign_keypair('hex')
  console.log(`SCEAU_PRIVATE_KEY=${keypair.privateKey}`)
  if (argv.pub) {
    console.log(`SCEAU_PUBLIC_KEY=${keypair.publicKey}`)
  }
}

if (argv._[0] === 'generate') {
  const buildURL = argv.build ?? env.SCEAU_BUILD_URL
  const sourceURL = argv.src ?? env.SCEAU_SOURCE_URL
  const privateKey = argv.privateKey ?? env.SCEAU_PRIVATE_KEY
  const packageDir = argv.packageDir ?? process.cwd()
  const sceau = await generate(sodium, {
    packageDir,
    privateKey,
    buildURL,
    sourceURL,
  })
  if (argv.addToPackageJson) {
    const packageJsonPath = path.resolve(packageDir, 'package.json')
    const packageJson = await fs.readJSON(packageJsonPath)
    packageJson.sceau = sceau
    await fs.writeJSON(packageJsonPath, packageJson, { spaces: 2 })
  }
  console.log(JSON.stringify(sceau, null, Boolean(argv.compact) ? 0 : 2))
}

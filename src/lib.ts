import Arborist from '@npmcli/arborist'
import chalk from 'chalk'
import fs from 'node:fs/promises'
import path from 'node:path'
import packlist from 'npm-packlist'
import { z } from 'zod'
import { numberToUint32LE } from './crypto/codec'
import {
  multipartSignature,
  verifyMultipartSignature,
} from './crypto/signature'
import type { Sodium } from './crypto/sodium'

export function keygen(sodium: Sodium, seed?: string) {
  const { publicKey, privateKey } = seed
    ? sodium.crypto_sign_seed_keypair(sodium.from_hex(seed), 'hex')
    : sodium.crypto_sign_keypair('hex')
  return { publicKey, privateKey }
}

// Schemas --

export const hexStringSchema = (bytes: number) =>
  z
    .string()
    .regex(
      new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'i'),
      `Expecting ${bytes} bytes in hexadecimal encoding (${
        bytes * 2
      } characters)`
    )

export const signatureSchema = hexStringSchema(64)

const manifestEntrySchema = z.object({
  path: z.string().describe('Relative file path (from the package root)'),
  hash: hexStringSchema(64).describe(
    'BLAKE2b hash of the file contents (64 byte output, no key, default parameters, hex encoding)'
  ),
  sizeBytes: z.number().int().positive().describe('Size of the file in bytes'),
  signature: signatureSchema.describe(
    'Ed25519ph signature of the path, hash and size in bytes.'
  ),
})

type ManifestEntry = z.infer<typeof manifestEntrySchema>

// --

const V1_SCHEMA_URL =
  'https://raw.githubusercontent.com/47ng/sceau/main/src/schemas/v1.schema.json'

export const sceauSchema = z.object({
  $schema: z
    .literal(V1_SCHEMA_URL)
    .describe(
      'JSON schema for this document, also used as a version indicator.'
    ),
  signature: signatureSchema.describe(
    'Ed25519ph signature\nSee https://github.com/47ng/sceau/blob/main/src/crypto/signature.ts'
  ),
  publicKey: hexStringSchema(32).describe(
    'Ed25519 public key associated with the private key used to compute the signature.'
  ),
  timestamp: z
    .string()
    .datetime({ precision: 3 })
    .describe('ISO-8601 timestamp of the signature date & time.'),
  sourceURL: z
    .string()
    .url()
    .describe(
      'Permalink to the source code at the state it was when being signed.'
    ),
  buildURL: z
    .string()
    .url()
    .describe(
      'Permalink to the public CI/CD run where this signature occurred.'
    ),
  manifest: z
    .array(manifestEntrySchema)
    .describe(
      'Each entry in the manifest represents an artifact file being published.'
    ),
})

export type Sceau = z.infer<typeof sceauSchema>

// --

export type ManifestEntryVerificationSuccess = {
  outcome: 'success'
}

export type ManifestEntryVerificationFailure = {
  outcome: 'failure'
  message: string
  path: string
} & (
  | {
      mismatchOn: 'presence'
      fileExists: false
    }
  | {
      mismatchOn: 'size'
      expected: number
      received: number
    }
  | {
      mismatchOn: 'hash'
      expected: string
      received: string
    }
  | {
      mismatchOn: 'signature'
      expected: string
    }
)

export type ManifestEntryVerificationResult =
  | ManifestEntryVerificationSuccess
  | ManifestEntryVerificationFailure

export type SceauVerificationSuccess = {
  outcome: 'success'
  timestamp: string
  sourceURL: string
  buildURL: string
}

export type SceauVerificationFailure = {
  outcome: 'failure'
  manifestErrors: ManifestEntryVerificationFailure[]
  signatureVerified: boolean
}

export type SceauVerificationResult =
  | SceauVerificationSuccess
  | SceauVerificationFailure

// --

async function signManifestEntry(
  sodium: Sodium,
  packageDir: string,
  relativeFilePath: string,
  privateKey: Uint8Array
): Promise<ManifestEntry> {
  const filePath = path.resolve(packageDir, relativeFilePath)
  const contents = await fs.readFile(filePath)
  const hash = sodium.crypto_generichash(64, contents, null)
  const sizeBytes = contents.byteLength
  const signature = multipartSignature(
    sodium,
    privateKey,
    sodium.from_string(relativeFilePath),
    hash,
    numberToUint32LE(sizeBytes)
  )
  return {
    path: relativeFilePath,
    hash: sodium.to_hex(hash),
    sizeBytes: contents.byteLength,
    signature: sodium.to_hex(signature),
  }
}

async function verifyManifestEntry(
  sodium: Sodium,
  packageDir: string,
  entry: ManifestEntry,
  publicKey: Uint8Array
): Promise<ManifestEntryVerificationResult> {
  const filePath = path.resolve(packageDir, entry.path)
  const stat = await fs.stat(filePath)
  if (!stat.isFile()) {
    return {
      outcome: 'failure',
      mismatchOn: 'presence',
      message: 'File not found',
      fileExists: false,
      path: entry.path,
    }
  }
  const contents = await fs.readFile(filePath)
  const sizeBytes = contents.byteLength
  if (sizeBytes !== entry.sizeBytes) {
    return {
      outcome: 'failure',
      mismatchOn: 'size',
      expected: entry.sizeBytes,
      received: sizeBytes,
      message: `Contents differ ${chalk.dim('(mismatching file size)')}`,
      path: entry.path,
    }
  }
  const hash = sodium.crypto_generichash(64, contents, null)
  if (!sodium.memcmp(hash, sodium.from_hex(entry.hash))) {
    return {
      outcome: 'failure',
      mismatchOn: 'hash',
      message: `Contents differ ${chalk.dim('(mismatching hash)')}`,
      expected: entry.hash,
      received: sodium.to_hex(hash),
      path: entry.path,
    }
  }
  if (
    !verifyMultipartSignature(
      sodium,
      publicKey,
      sodium.from_hex(entry.signature),
      sodium.from_string(entry.path),
      hash,
      numberToUint32LE(sizeBytes)
    )
  ) {
    return {
      outcome: 'failure',
      mismatchOn: 'signature',
      message: 'Invalid signature',
      expected: entry.signature,
      path: entry.path,
    }
  }
  return {
    outcome: 'success',
  }
}

// --

async function signManifest(
  sodium: Sodium,
  packageDir: string,
  ignorePatterns: RegExp[],
  privateKey: Uint8Array
) {
  const arborist = new Arborist({ path: packageDir })
  const tree = await arborist.loadActual()
  const files = (await packlist(tree)).filter(
    file => !ignorePatterns.some(pattern => pattern.test(file))
  )
  files.sort()
  return Promise.all(
    files.map(filePath =>
      signManifestEntry(sodium, packageDir, filePath, privateKey)
    )
  )
}

async function verifyManifest(
  sodium: Sodium,
  packageDir: string,
  publicKey: Uint8Array,
  manifest: ManifestEntry[]
) {
  const results = await Promise.all(
    manifest.map(entry =>
      verifyManifestEntry(sodium, packageDir, entry, publicKey)
    )
  )
  return results.filter(
    result => result.outcome === 'failure'
  ) as ManifestEntryVerificationFailure[]
}

type SignInput = Pick<Sceau, 'sourceURL' | 'buildURL'> & {
  timestamp: Date
  /**
   * Absolute path to the package to sign
   */
  packageDir: string
  /**
   * Ed25519 private key to use for signature (64 bytes hex encoded)
   */
  privateKey: string
  /** A list of files to omit from the manifest
   *
   * Note that this should always include the sceau file itself,
   * otherwise signature will be impossible (running in circles).
   */
  ignorePatterns: RegExp[]
}

export async function sign(
  sodium: Sodium,
  {
    packageDir,
    sourceURL,
    buildURL,
    privateKey,
    ignorePatterns,
    timestamp: timestampDate,
  }: SignInput
) {
  // Verify private key format
  hexStringSchema(64).parse(privateKey)
  const secretKey = sodium.from_hex(privateKey)
  const publicKey = sodium.to_hex(secretKey.slice(32, 64))
  const manifest = await signManifest(
    sodium,
    packageDir,
    ignorePatterns,
    secretKey
  )
  const $schema = V1_SCHEMA_URL
  const timestamp = timestampDate.toISOString()
  const signature = multipartSignature(
    sodium,
    secretKey,
    sodium.from_string($schema),
    sodium.from_string(timestamp),
    sodium.from_string(sourceURL),
    sodium.from_string(buildURL),
    ...manifest.map(entry => sodium.from_hex(entry.hash))
  )
  sodium.memzero(secretKey)
  const sceau: Sceau = {
    $schema,
    signature: sodium.to_hex(signature),
    publicKey,
    timestamp,
    sourceURL,
    buildURL,
    manifest,
  }
  return sceau
}

export async function verify(
  sodium: Sodium,
  sceau: Sceau,
  packageDir: string,
  publicKey: Uint8Array
): Promise<SceauVerificationResult> {
  if (new Date(sceau.timestamp).valueOf() > Date.now()) {
    throw new Error('Signature timestamp is in the future')
  }
  const manifestErrors = await verifyManifest(
    sodium,
    packageDir,
    publicKey,
    sceau.manifest
  )
  const signatureVerified = verifyMultipartSignature(
    sodium,
    publicKey,
    sodium.from_hex(sceau.signature),
    sodium.from_string(sceau.$schema),
    sodium.from_string(sceau.timestamp),
    sodium.from_string(sceau.sourceURL),
    sodium.from_string(sceau.buildURL),
    ...sceau.manifest.map(entry => sodium.from_hex(entry.hash))
  )
  if (manifestErrors.length > 0 || !signatureVerified) {
    return {
      outcome: 'failure',
      manifestErrors,
      signatureVerified,
    }
  }
  return {
    outcome: 'success',
    timestamp: sceau.timestamp,
    sourceURL: sceau.sourceURL,
    buildURL: sceau.buildURL,
  }
}

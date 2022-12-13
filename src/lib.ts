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

export const hexStringSchema = (bytes: number) =>
  z
    .string()
    .regex(
      new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'i'),
      `Expecting ${bytes} bytes in hexadecimal encoding (${
        bytes * 2
      } characters)`
    )

const signatureSchema = hexStringSchema(64)

export const manifestEntrySchema = z.object({
  path: z.string(),
  hash: hexStringSchema(64),
  sizeBytes: z.number().int().positive(),
  signature: signatureSchema,
})

export type ManifestEntry = z.infer<typeof manifestEntrySchema>

// --

const V1_SCHEMA_URL =
  'https://raw.githubusercontent.com/47ng/sceau/main/src/schemas/v1.schema.json'

export const sceauSchema = z.object({
  $schema: z.literal(V1_SCHEMA_URL),
  signature: signatureSchema,
  publicKey: hexStringSchema(32),
  timestamp: z.string().datetime({ precision: 3 }),
  sourceURL: z.string().url(),
  buildURL: z.string().url(),
  manifest: z.array(manifestEntrySchema),
})

export type Sceau = z.infer<typeof sceauSchema>

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
) {
  function error(reason: string): never {
    throw new Error(
      `${chalk.red.bold(entry.path)} Contents differ ${chalk.dim(
        `(${reason})`
      )}`
    )
  }
  const filePath = path.resolve(packageDir, entry.path)
  const contents = await fs.readFile(filePath)
  const sizeBytes = contents.byteLength
  if (sizeBytes !== entry.sizeBytes) {
    error('mismatching file size')
  }
  const hash = sodium.crypto_generichash(64, contents, null)
  if (!sodium.memcmp(hash, sodium.from_hex(entry.hash))) {
    error('mismatching hash')
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
    throw new Error(`${chalk.red.bold(entry.path)} Invalid signature`)
  }
  return true
}

// --

async function signManifest(
  sodium: Sodium,
  packageDir: string,
  ignoreFiles: string[],
  privateKey: Uint8Array
) {
  const arborist = new Arborist({ path: packageDir })
  const tree = await arborist.loadActual()
  const files = (await packlist(tree)).filter(
    file => !ignoreFiles.includes(file)
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
  const result = await Promise.allSettled(
    manifest.map(entry =>
      verifyManifestEntry(sodium, packageDir, entry, publicKey)
    )
  )
  const errors = result.filter(
    p => p.status === 'rejected'
  ) as PromiseRejectedResult[]
  if (errors.length) {
    throw new Error(
      errors.map(e => e.reason?.message ?? String(e.reason)).join('\n')
    )
  }
}

const signInputSchema = sceauSchema
  .pick({
    sourceURL: true,
    buildURL: true,
  })
  .extend({
    packageDir: z.string(),
    privateKey: hexStringSchema(64),
    ignoreFiles: z.array(z.string()).default([]),
  })

type SignInput = z.infer<typeof signInputSchema>

export async function sign(sodium: Sodium, input: SignInput) {
  const { packageDir, sourceURL, buildURL, privateKey, ignoreFiles } =
    signInputSchema.parse(input)
  const secretKey = sodium.from_hex(privateKey)
  const publicKey = sodium.to_hex(secretKey.slice(32, 64))
  const manifest = await signManifest(
    sodium,
    packageDir,
    ignoreFiles,
    secretKey
  )
  const $schema = V1_SCHEMA_URL
  const timestamp = new Date().toISOString()
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
) {
  if (new Date(sceau.timestamp).valueOf() > Date.now()) {
    throw new Error('Signature timestamp is in the future')
  }
  await verifyManifest(sodium, packageDir, publicKey, sceau.manifest)
  if (
    !verifyMultipartSignature(
      sodium,
      publicKey,
      sodium.from_hex(sceau.signature),
      sodium.from_string(sceau.$schema),
      sodium.from_string(sceau.timestamp),
      sodium.from_string(sceau.sourceURL),
      sodium.from_string(sceau.buildURL),
      ...sceau.manifest.map(entry => sodium.from_hex(entry.hash))
    )
  ) {
    throw new Error('Invalid package signature')
  }
  return true
}

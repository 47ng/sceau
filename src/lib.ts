import Arborist from '@npmcli/arborist'
import fs from 'node:fs/promises'
import packlist from 'npm-packlist'
import { z } from 'zod'
import { numberToUint32LE } from './crypto/codec'
import { multipartSignature } from './crypto/signature'
import type { Sodium } from './crypto/sodium'

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

export const sceauSchema = z.object({
  signature: signatureSchema,
  publicKey: hexStringSchema(32),
  timestamp: z.string().datetime({ precision: 3 }),
  sourceURL: z.string().url(),
  buildURL: z.string().url(),
  manifest: z.array(manifestEntrySchema),
})

export type Sceau = z.infer<typeof sceauSchema>

async function getManifestEntry(
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
    sodium.from_string(filePath),
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

async function getManifest(
  sodium: Sodium,
  packageDir: string,
  privateKey: Uint8Array
) {
  const arborist = new Arborist({ path: packageDir })
  const tree = await arborist.loadActual()
  const files = await packlist(tree)
  files.sort()
  return Promise.all(
    files.map(filePath =>
      getManifestEntry(sodium, packageDir, filePath, privateKey)
    )
  )
}

const sceauInputSchema = sceauSchema
  .pick({
    sourceURL: true,
    buildURL: true,
  })
  .extend({
    packageDir: z.string(),
    privateKey: hexStringSchema(64),
  })

type SceauInput = z.infer<typeof sceauInputSchema>

export async function generate(sodium: Sodium, input: SceauInput) {
  const { packageDir, sourceURL, buildURL, privateKey } =
    sceauInputSchema.parse(input)
  const secretKey = sodium.from_hex(privateKey)
  const publicKey = sodium.to_hex(secretKey.slice(32, 64))
  const manifest = await getManifest(sodium, packageDir, secretKey)
  const timestamp = new Date().toISOString()
  const signature = multipartSignature(
    sodium,
    secretKey,
    sodium.from_string(timestamp),
    sodium.from_string(sourceURL),
    sodium.from_string(buildURL),
    ...manifest.map(entry => sodium.from_hex(entry.hash))
  )
  sodium.memzero(secretKey)
  const sceau: Sceau = {
    signature: sodium.to_hex(signature),
    publicKey,
    timestamp,
    sourceURL,
    buildURL,
    manifest,
  }
  return sceau
}

export async function verify(sodium: Sodium, sceau: Sceau, packageDir: string) {
  // todo: Implement me
}

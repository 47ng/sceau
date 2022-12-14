import chalk from 'chalk'
import minimist from 'minimist'
import { z } from 'zod'
import { SCEAU_FILE_NAME } from '../constants'
import { hexStringSchema } from '../lib'

const keygenCommandSchema = z.object({
  command: z.literal('keygen'),
  seed: hexStringSchema(32).optional(),
  compact: z.boolean().optional().default(false),
})

export type KeygenCommandArgs = Omit<
  z.infer<typeof keygenCommandSchema>,
  'command'
>

// --

const signCommandSchema = z.object({
  command: z.literal('sign'),
  build: z.string().url().optional(),
  source: z.string().url().optional(),
  privateKey: hexStringSchema(64).optional(),
  packageDir: z.string().optional(),
  file: z.string().optional().default(SCEAU_FILE_NAME),
  quiet: z.boolean().optional().default(false),
  ignore: z
    .union([z.string().transform(str => [str]), z.array(z.string()).optional()])
    .optional()
    .default([]),
})

export type SignCommandArgs = Omit<z.infer<typeof signCommandSchema>, 'command'>

// --

const verifyCommandSchema = z.object({
  command: z.literal('verify'),
  packageDir: z.string().optional(),
  publicKey: hexStringSchema(32).optional(),
  file: z.string().optional().default(SCEAU_FILE_NAME),
  strict: z.boolean().optional().default(false),
})

export type VerifyCommandArgs = Omit<
  z.infer<typeof verifyCommandSchema>,
  'command'
>

// --

const sceauCommands = z.discriminatedUnion('command', [
  keygenCommandSchema,
  signCommandSchema,
  verifyCommandSchema,
])

export function parseArgs() {
  const { _, ...args } = minimist(process.argv.slice(2))
  const result = sceauCommands.safeParse({
    command: _[0],
    ...args,
  })
  if (!result.success) {
    console.error(result.error.format())
    console.info(`
${chalk.bold('Code signing for NPM packages')}

Commands & options:

${chalk.green('##')} ${chalk.bold('sceau keygen')}

  Generate a signature private key (Ed25519).

  Options:
    --seed [32 bytes hex]   Generate a deterministic private key from the given seed
    --compact               Only output the private key value without description


${chalk.green('##')} ${chalk.bold('sceau sign')}

  List publishable files, hash and sign their contents,
  then add metadata and sign the whole thing.

  Inputs ${chalk.dim('(can be passed as CLI args or environment variables):')}
    --source [url]          env: SCEAU_SOURCE_URL   Permalink to the source code
    --build [url]           env: SCEAU_BUILD_URL    Permalink to the public CI/CD run
    --privateKey [key]      env: SCEAU_PRIVATE_KEY  Signature private key

  Options:
    --packageDir [path]     Path to the package to process (default: \`cwd\`)
    --file [path]           Store the output into the given JSON file, relative to packageDir (default: \`sceau.json\`)
    --ignore [regex]        Ignore files matching the regular expression (can be passed multiple times)
    --quiet                 Don't print any output


${chalk.green('##')} ${chalk.bold('sceau verify')}

    Verify a signed package and display associated metadata

    Options:
      --packageDir [path]     Path to the package to process (default: \`cwd\`)
      --file [path]           Path to the sceau file (default: \`sceau.json\`)
      --publicKey [key]       env: SCEAU_PUBLIC_KEY  Signature public key to use for verification (defaults to using the embedded one)
      --strict                Fail if package is not signed
  `)
    process.exit(1)
  }
  return result.data
}

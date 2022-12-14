<h1 align="center">🔏 <code>sceau</code></h1>

<div align="center">

[![NPM](https://img.shields.io/npm/v/sceau?color=red)](https://www.npmjs.com/package/sceau)
[![MIT License](https://img.shields.io/github/license/47ng/sceau.svg?color=blue)](https://github.com/47ng/sceau/blob/next/LICENSE)
[![CI/CD](https://github.com/47ng/sceau/workflows/CI%2FCD/badge.svg?branch=next)](https://github.com/47ng/sceau/actions)
[![Coverage Status](https://coveralls.io/repos/github/47ng/sceau/badge.svg?branch=next)](https://coveralls.io/github/47ng/sceau?branch=next)

</div>

<p align="center">
  Code signing for NPM packages
</p>

## Installation

Using your favourite package manager:

```
pnpm add -D sceau
yarn add -D sceau
npm install -D sceau
```

## CLI usage

First off, you'll need a signature private key.

### Keygen

You can generate one from the CLI:

```
$ sceau keygen

Run the following command in your terminal to use this private key:

export SCEAU_PRIVATE_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

Associated public key:
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

This will give you an environment variable definition for the private key,
and the associated public key.

> **Note about keys:**
> The underlying signature is Ed25519, which stores the public key as part of
> the private key.
>
> If you misplace your public key, it can be obtained from the private key:
> the public key is the **LAST half** (64 hex characters) of the private key.

### Signing packages

To sign a package, run the following command:

```
$ sceau sign
```

This will:

1. Collect a list of files to be published (based on the `files` option in package.json and the .npmignore file)
2. Hash and sign each file into a manifest
3. Inject some metadata, like:

- A [URL to the JSON schema](https://raw.githubusercontent.com/47ng/sceau/main/src/schemas/v1.schema.json) of the resulting file, serving as a version identifier
- The current time
- A permalink to the sources _(see [CI usage](#ci-usage))_
- A permalink to the build process _(see [CI usage](#ci-usage))_

4. Sign the whole thing
5. Store it in a `sceau.json` file next to package.json

#### CI usage

Links to source and build process are injected to provide transparency and
traceability to a package being built.

The idea is that the signing step would occur in a public CI/CD context.

You can specify the URLs to the sources and build process either via the command-line,
or via environment variables:

| CLI argument | Environment variable | Description                    |
| ------------ | -------------------- | ------------------------------ |
| `--source`   | `SCEAU_SOURCE_URL`   | Permalink to the source code   |
| `--build`    | `SCEAU_BUILD_URL`    | Permalink to the build process |

> Note: those two URLs are automatically populated for you if sceau runs in a
> GitHub Actions context. PRs for more CI contributions are welcome!

If those are not provided, sceau will still sign your package, but the URLs
will be set to `unknown://local`.

Sceau will write to a file, but will also print to the standard output, so this
signature process can be audited by third parties.

#### Setting up package.json

Because sceau should run right before NPM packs your artifacts to publish them,
you should run the signature step in the `prepack` script:

```jsonc
{
  "files": [
    // ...
    "sceau.json"
  ],
  "scripts": {
    "prepack": "sceau sign"
  }
}
```

Note that it's also required to add `sceau.json` to the list of files, otherwise
the signature would be left behind when your package is packed.

#### Options

`--packageDir` lets you specify a path to a pacakge to sign.
By default, sceau will try to look for a package to sign at the current working
directory.

`--file` lets you choose the output file (defaults to `sceau.json`). It should
be a path relative to the package directory (where package.json is located).

Example:

```
$ sceau sign --packageDir packages/my-package --file build/signature.json
```

This will sign package `<cwd>/packages/my-package`, and store the output at
`<cwd>/packages/my-package/build/signature.json`.

`--ignore` lets you specify RegExp patterns to match against file paths.
Files matching those patterns won't be included in the manifest and therefore
won't be part of the final signature.

Note that the output file is always automatically included in those patterns.

### Verifying

You can verify a package signed with sceau using the following command:

```
$ sceau verify --packageDir path/to/package
```

#### Options

You should provide the public key to verify a signature against, obtained from
a trusted source (ideally one not under GitHub's or NPM's control, in case those
were to be compromised).

```
$ sceau verify --publicKey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

If the package uses a non-standard `<packageDir>/sceau.json` signature file,
you can specify its location (relative to the package directory):

```
$ sceau verify --file build/signature.json
```

By default, calling verify on an unsigned package will only print that fact
and exit cleanly. If you expect a package to be signed, you can use strict
verification, that will fail on unsigned packages:

```
$ sceau verify --strict
```

## Programmatic usage

Sceau can be imported as a library (ESM only).

You can access the commands using the same arguments as the CLI:

```ts
import {
  generateKeyPair,
  signCommand,
  verifyCommand,
  SCEAU_FILE_NAME,
} from 'sceau'

// Random keypair
const { publicKey, privateKey } = await generateKeyPair()

// Seeded keypair
const { publicKey, privateKey } = await generateKeyPair('baadf00d...')

await signCommand({
  file: SCEAU_FILE_NAME,
  quiet: true,
  privateKey: '...', // will default to SCEAU_PRIVATE_KEY env if unspecified
  packageDir: 'packages/my-package',
  build: 'https://url-to-build-process.example.com',
  source: 'https://url-to-sources.example.com',
})

await verifyCommand({
  file: SCEAU_FILE_NAME,
  strict: true,
  packageDir: 'packages/my-package',
  publicKey: '...', // will default to SCEAU_PUBLIC_KEY env if unspecified
})
```

## Examples

Sceau [signs itself](.github/workflows/ci-cd.yml) when released.

You can verify a sceau install (using itself too):

```
sceau verify --strict --publicKey c30d5d28b88136c77168fb78bf117948127c4e22f987ab60cd083bbd6c7ac0c9
```

We use semantic-release, which injects the NPM package version just
before publishing. In order to sign the final package.json file,
we run `sceau sign` as the `prepack` lifecycle hook.

The private key is passed as an environment variable to the calling
step (semantic-release).

## Cryptography

Cryptography is provided by [libsodium](https://github.com/jedisct1/libsodium.js).

- Hash: BLAKE2b, 64 byte output, no key, default parameters
- Signature: Ed25519ph (SHA-512 pre-hash), with manifest header.

See [signature.ts](./src/crypto/signature.ts) for more details.

## About the name

_Sceau_ is French for _seal_ (the ones found on letters, not in oceans).

It's pronounced like _so_.

## License

[MIT](https://github.com/47ng/sceau/blob/master/LICENSE) - Made with ❤️ by [François Best](https://francoisbest.com)

Using this package at work ? [Sponsor me](https://github.com/sponsors/franky47) to help with support and maintenance.

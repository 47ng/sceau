export type { SignCommandArgs, VerifyCommandArgs } from './cli/args'
// CLI command interfaces
export { generateKeyPair } from './cli/commands/keygen'
export { signCommand } from './cli/commands/sign'
export { verifyCommand } from './cli/commands/verify'
// Low-level API
export { SCEAU_FILE_NAME } from './constants'
export { initializeSodium } from './crypto/sodium'
export { keygen, sceauSchema, sign, verify } from './lib'
export type {
  ManifestEntryVerificationFailure,
  ManifestEntryVerificationResult,
  ManifestEntryVerificationSuccess,
  Sceau,
  SceauVerificationFailure,
  SceauVerificationResult,
  SceauVerificationSuccess,
} from './lib'

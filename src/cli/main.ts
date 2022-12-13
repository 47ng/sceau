import { parseArgs } from './args'
import { keygenCommand } from './commands/keygen'
import { signCommand } from './commands/sign'
import { verifyCommand } from './commands/verify'

export async function main() {
  const args = parseArgs()
  if (args.command === 'keygen') {
    return keygenCommand(args)
  }
  if (args.command === 'sign') {
    return signCommand(args)
  }
  if (args.command === 'verify') {
    return verifyCommand(args)
  }
}

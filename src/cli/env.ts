import { z } from 'zod'
import { hexStringSchema } from '../lib'

const DEFAULT_URL = 'unknown://local'

const envSchema = z.object({
  SCEAU_PRIVATE_KEY: hexStringSchema(64).optional(),
  SCEAU_PUBLIC_KEY: hexStringSchema(32).optional(),
  // todo: Detect build & source URLs based on environment (GitHub Actions)
  SCEAU_BUILD_URL: z.string().url().optional().default(DEFAULT_URL),
  SCEAU_SOURCE_URL: z.string().url().optional().default(DEFAULT_URL),
})

export const env = envSchema.parse(process.env)

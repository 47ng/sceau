import { z } from 'zod'
import { hexStringSchema } from '../lib'

const DEFAULT_URL = 'unknown://local'

const gitHubActionsSchema = z.object({
  CI: z.literal('true'),
  GITHUB_SHA: hexStringSchema(20),
  GITHUB_RUN_ID: z.string(),
  GITHUB_REPOSITORY: z.string(),
  GITHUB_SERVER_URL: z.string().url(),
})

function getContextURLs() {
  const gha = gitHubActionsSchema.safeParse(process.env)
  if (gha.success) {
    const { GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_SERVER_URL, GITHUB_SHA } =
      gha.data
    return {
      sourceURL: `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/tree/${GITHUB_SHA}`,
      buildURL: `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}`,
    }
  }
  return {
    sourceURL: DEFAULT_URL,
    buildURL: DEFAULT_URL,
  }
}

const { sourceURL, buildURL } = getContextURLs()

const envSchema = z.object({
  SCEAU_PRIVATE_KEY: hexStringSchema(64).optional(),
  SCEAU_PUBLIC_KEY: hexStringSchema(32).optional(),
  SCEAU_BUILD_URL: z.string().url().optional().default(buildURL),
  SCEAU_SOURCE_URL: z.string().url().optional().default(sourceURL),
})

export const env = envSchema.parse(process.env)

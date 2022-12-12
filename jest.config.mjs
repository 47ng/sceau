/** @type {import('ts-jest').JestConfigWithTsJest} */
const jestConfig = {
  preset: 'ts-jest',
  // testEnvironment: 'jsdom',
  verbose: true,
  transform: {
    '^.+\\.ts$': ['@swc/jest'],
  },
  testMatch: ['<rootDir>/src/**/*.test.ts'],
  // transformIgnorePatterns: ['node_modules/(?!(@47ng/chakra-next)/)'],
  // ESM support
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  extensionsToTreatAsEsm: ['.ts'],
}

export default jestConfig

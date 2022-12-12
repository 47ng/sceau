import { numberToUint32LE } from './codec'

describe('codec', () => {
  test('numberToUint32LE', () => {
    expect(numberToUint32LE(0)).toEqual(new Uint8Array([0, 0, 0, 0]))
  })
})

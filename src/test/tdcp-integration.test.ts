import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runTDCPTestSuite } from './tdcp-test-runner.ts';
import { base64ToByteLength, base64ToUint8Array, arrayBufferToBase64 } from '../core/crypto/primitives.ts';

describe('TDCP Gatekeeper integration', () => {
  it('runs the full suite with no false guarantees', async () => {
    const summary = await runTDCPTestSuite();
    const failed = summary.results.filter((r) => r.status === 'FAIL');
    assert.equal(
      failed.length,
      0,
      failed.map((f) => `#${f.id} ${f.name}: ${f.actualResult}`).join('\n')
    );
    assert.ok(summary.totalTests >= 20);
  });

  it('base64ToByteLength calculates decoded byte length with zero allocations', () => {
    assert.equal(base64ToByteLength(''), 0);

    // Test multiple lengths across 0, 1, 2 padding characters
    for (let len = 1; len <= 64; len++) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 31 + 7) & 0xff;
      const b64 = arrayBufferToBase64(bytes);
      assert.equal(base64ToByteLength(b64), len);
      assert.equal(base64ToByteLength(b64), base64ToUint8Array(b64).byteLength);
    }

    // Invalid base64 inputs must throw
    assert.throws(() => base64ToByteLength('abc'), /INVALID_BASE64_ENCODING/);
    assert.throws(() => base64ToByteLength('invalid base64!'), /INVALID_BASE64_ENCODING/);
    assert.throws(() => base64ToByteLength('==='), /INVALID_BASE64_ENCODING/);
    assert.throws(() => base64ToByteLength('a==='), /INVALID_BASE64_ENCODING/);
  });
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runTDCPTestSuite } from './tdcp-test-runner.ts';

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
});

import { runTDCPTestSuite } from '../src/test/tdcp-test-runner.ts';

async function main() {
  console.log('TDCP security suite');
  const summary = await runTDCPTestSuite((current, _total, result) => {
    const icon = result.status === 'PASS' ? 'PASS' : 'FAIL';
    console.log(`[${current}] ${icon} ${result.id}: ${result.name} (${result.durationMs}ms)`);
    console.log(`       ${result.actualResult}`);
  });
  console.log(`TOTAL ${summary.totalTests}  PASS ${summary.passedCount}  FAIL ${summary.failedCount}  ${summary.totalDurationMs}ms`);
  if (!summary.allPassed) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

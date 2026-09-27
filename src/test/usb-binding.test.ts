import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bindingDigest,
  buildCsgInput,
  hardwareDigest,
  validateUsbBinding,
  type HardwareSnapshot,
  type UsbBindingRecord,
} from '../device/usb-binding.ts';

const hardware: HardwareSnapshot = {
  vendorId: 0x1234,
  productId: 0xabcd,
  serialNumber: 'USB-ORIGINAL-001',
  manufacturerName: 'Example',
  productName: 'Secure Storage',
  usbVersionMajor: 3,
  usbVersionMinor: 1,
  interfaceClasses: [8, 0],
};

const token = {
  artifactId: 'stok-device-001',
  authorizationDigest: 'auth-digest-001',
};

const binding = {
  schema: 'tdcp.usb-binding.v1' as const,
  deviceId: 'usb-device-001',
  accountId: 'account-001',
  hardware,
  validationMode: 'persistent' as const,
  createdAt: 1000,
  expiresAt: null,
};

const record: UsbBindingRecord = {
  version: 1,
  binding,
  hardwareDigest: 'PLACEHOLDER',
  smartToken: token,
  csg: {
    sealId: 'csg-001',
    digest: 'csg-digest-001',
    algorithm: 'external-csg',
  },
  status: 'ACTIVE',
};

record.hardwareDigest = await hardwareDigest(hardware);

test('same hardware snapshot produces the same digest', async () => {
  assert.equal(await hardwareDigest(hardware), await hardwareDigest({ ...hardware, interfaceClasses: [0, 8] }));
});

test('binding digest changes when the bound hardware changes', async () => {
  const changed = { ...hardware, serialNumber: 'USB-CLONE-002' };
  assert.notEqual(await bindingDigest(binding), await bindingDigest({ ...binding, hardware: changed }));
});

test('CSG input is deterministic', async () => {
  assert.equal(await buildCsgInput(binding, token), await buildCsgInput(binding, token));
});

test('exact hardware + token + CSG passes', async () => {
  const result = await validateUsbBinding(hardware, record, token, 'csg-digest-001', 2000);
  assert.deepEqual(result, { valid: true, reason: 'MATCH', binding: record });
});

test('hardware mismatch is rejected', async () => {
  const result = await validateUsbBinding(
    { ...hardware, serialNumber: 'USB-CLONE-002' },
    record,
    token,
    'csg-digest-001',
    2000
  );
  assert.equal(result.valid, false);
  if (!result.valid) assert.equal(result.reason, 'HARDWARE_MISMATCH');
});

test('CSG mismatch is rejected', async () => {
  const result = await validateUsbBinding(hardware, record, token, 'tampered-csg', 2000);
  assert.equal(result.valid, false);
  if (!result.valid) assert.equal(result.reason, 'CSG_MISMATCH');
});

test('revoked binding is rejected', async () => {
  const result = await validateUsbBinding(hardware, { ...record, status: 'REVOKED' }, token, 'csg-digest-001', 2000);
  assert.equal(result.valid, false);
  if (!result.valid) assert.equal(result.reason, 'REVOKED');
});

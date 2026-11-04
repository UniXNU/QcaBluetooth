# iPadOS 27 native adapter

The adapter targets the original arm64e `bluetoothd` from 24A446:

- SHA-256: `cfd94854d0a2efd3ca4a2de6e55349f43fd0d274a4b8bfa9937f29d9f7208cb1`
- UUID: `8E49197B-E6BC-3F3B-A8D3-DF4BEDD37F01`

`tools/patch-ios27.py` creates the patched executable and a JSON report.
`tools/build-type0.py` builds and signs `/usr/lib/QcaBTType0.dylib`. Payload
installation, executable signing and device verification are pending.
Apple binaries remain external inputs.

## Routing

The three BCM4357 factory arguments select controller type zero. Registration
accepts zero and preserves the native 1 through 6000 range. Type zero clears
the vendor operation table, four vendor hooks and both vendor opcodes. Both
callback registration paths retain their generic callback. Other controller
types retain their native paths.

Optional command 0x0c5b follows byte 18, bit 3 of the native support bitmap;
unsupported controllers advance through the native initialization chain.
H4 pre-stop skips its empty extension and retains normal transport close.

## Capabilities

The adapter reads Supported Commands and LE Features. Extended scanning,
connection, advertising, periodic advertising, sync transfer, coded PHY and
2M PHY follow the controller's reports. Both LE feature callback versions
preserve their original status and data pointer for capability publication.

An asynchronous LE Read Number of Supported Advertising Sets query supplies the
broadcast capacity. The count is capped at the native array's six records.
Query failures reach the native error path. Model getters, configuration caches
and lower stack flags receive the same capabilities. The broadcaster refreshes
its mode before native GAP initialization, including after reopen.

The library runs during initialization. Normal packet traffic stays in the
native stack and UART.SK. The eleven replacement getters use four instructions
each. Dyld signs their USERLAND24 rebases with the original keys and diversity;
object vtable pointers remain intact. Callback and broadcaster entry patches
retain their original PACIBSP landing pads. Native function calls use signed
IA/0 pointers. The layout follows Apple's
[dyld header](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).

## Build and verification

From the component checkout, with the original binary at `$BLUETOOTHD`:

```sh
python3 -m venv out/native-venv
out/native-venv/bin/pip install -r tools/requirements-native.txt
out/native-venv/bin/python tools/test-native.py "$BLUETOOTHD"
python3 tools/test-type0.py "$BLUETOOTHD"
python3 tools/build-type0.py
python3 tools/patch-ios27.py "$BLUETOOTHD" --output out/ios27/bluetoothd.native
```

The 144 instruction cases execute native routing, feature capture, authenticated
call boundaries, getters, lower setters and H4 pre-stop at two ASLR slides.
PAC operations are modeled without device keys. The production C publisher
passes 58 HCI and policy cases under ASan/UBSan, including command and feature
absence, capacity limits, failed replies, submit errors and reopen mode changes.
The arm64e library compiles and passes code-signature verification. Reports
reside in `out/native-test`, `out/type0-test` and `out/userland`.

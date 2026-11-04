# iPadOS 27 native routing

The adapter targets the original arm64e `bluetoothd` from 24A446:

- SHA-256: `cfd94854d0a2efd3ca4a2de6e55349f43fd0d274a4b8bfa9937f29d9f7208cb1`
- UUID: `8E49197B-E6BC-3F3B-A8D3-DF4BEDD37F01`

`tools/patch-ios27.py` produces the vendor-routing stage and a JSON report.
The report has `adapter_ready=false`: capability publication and
payload installation remain in development. Apple binaries stay external.

## Routing

The three BCM4357 factory arguments select controller type zero. Registration
accepts zero and preserves the native 1 through 6000 range. Type zero clears
the vendor operation table, four vendor hooks and both vendor opcodes. Both
callback registration paths retain their generic callback and skip vendor
callback installation. Other controller types retain their original paths.

The optional Write Default Erroneous Data Reporting command runs when byte 18,
bit 3 in the native support bitmap is set. Otherwise the native initialization
chain advances directly. The adapter generates no controller reply.

H4 pre-stop at `0x1003083cc` skips the empty extension in the native H4 table at
`0x100c1cd50`. Native handling of other transports and the regular close callback
remain intact.

Trampolines occupy the empty executable tail at `0x100b9bba0`. Existing frames
and pointer authentication instructions remain in effect. The image inspector
reads USERLAND24 chained fixups, import stubs and function boundaries. It
identifies ten capability slots in the model vtable at `0x100bafcf8`; their
signing diversity, address diversity and key remain unchanged in this stage.
The fixup layout follows Apple's
[dyld header](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).

## Verification

From the component checkout, with the original binary at `$BLUETOOTHD`:

```sh
python3 -m venv out/native-venv
out/native-venv/bin/pip install -r tools/requirements-native.txt
out/native-venv/bin/python tools/test-native.py "$BLUETOOTHD"
python3 tools/patch-ios27.py "$BLUETOOTHD" --output out/ios27/bluetoothd.vendor-stage
```

The 76 instruction cases cover registration boundaries, vendor table clearing,
generic callback preservation, optional command selection, H4 pre-stop and two
ASLR slides.
They execute the original and patched AArch64 instructions. PAC operations are
modeled without device keys. The check also verifies edit boundaries and rejects
a changed input hash. Reports are written under `out/native-test` and beside
the generated stage. Device execution is pending.

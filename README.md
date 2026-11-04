# QcaBluetooth

Qualcomm WCN7850 Bluetooth support for XNU. The implementation uses the original
Linux `btqca.c` startup sequence and Apple's native Bluetooth protocol stack.

## Interfaces

- `include/qbt.h`: one executor owns Linux initialization, H4 framing and IBS.
  The platform supplies memory, firmware, UART operations and event waits.
- `include/qbt_geni.h`: GENI SE DMA with four 2048-byte RX buffers and one
  4096-byte TX buffer. The board supplies mapped DMA addresses and IRQ masking.
- `include/qbt_transport.h`: UART.SK kernel pipe, ring backpressure, channel
  lifetime and worker power requests through `kern.sheng_bt_control`.
- `userland/BlueTool.c`: `com.apple.BlueTool` XPC bootstrap service. Pairing,
  key storage, BLE and audio profiles run in the system's `bluetoothd`.

`tools/prepare-linux.py` verifies the source hash before staging byte-identical
Linux code in `out/linux`. `QBT_LINUX_TREE` selects an existing Linux checkout.
The source lock records the Linux, board and Renoir transport references.

## Checks

```sh
python3 tools/test-runtime.py
python3 tools/test-geni.py
python3 tools/check-kernel.py /path/to/assembled/tree
python3 tools/build-bluetool.py
```

The runtime check covers actual Linux initialization, NVM edits, firmware
fallback, timeouts, H4 fragmentation and backpressure, and IBS at TX packet
boundaries. The DMA check covers buffer ownership, address width, wire drain,
flow control, quiesce/resume and faults. Both run with address and undefined
behavior sanitizers. The kernel check uses the target's BSD compilation record
and checks symbol names and availability in the built kernel.

`tools/inspect-ios.py` records a local `bluetoothd` identity and transport/model
call sites. The arm64e BlueTool build is signed and includes a launchd job.

The component passes host simulation and iPadOS 27 arm64e source compilation.
The sheng source integration binds UART14 clocks, IRQ, DMA and GPIO wake to its
worker. Runtime payload installation and native controller adaptation are in
development; device scanning, pairing and audio are pending.

## Sources and licenses

Linux initialization and GENI/H4/IBS code use GPL-2.0-only. The UART.SK adapter
derives from the Renoir APSL-2.0 transport; its companion notice preserves that
license. Public platform interfaces and the BlueTool service use
BSD-2-Clause-Patent as identified in each file. Vendor firmware and Apple
binaries are external inputs and remain outside source control.

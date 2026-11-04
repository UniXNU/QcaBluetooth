# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Version-locked native iPadOS 27 Bluetooth routing and image metadata."""
import hashlib
import importlib.util
import struct
from pathlib import Path

_spec = importlib.util.spec_from_file_location('qbt_inspect_ios', Path(__file__).with_name('inspect-ios.py'))
_inspect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_inspect)

ORIGINAL_SHA256 = 'cfd94854d0a2efd3ca4a2de6e55349f43fd0d274a4b8bfa9937f29d9f7208cb1'
ORIGINAL_UUID = '8E49197B-E6BC-3F3B-A8D3-DF4BEDD37F01'
BASE = 0x100000000
CAVE = 0x100b9bba0
CAVE_END = 0x100b9c000
DESCRIPTORS = 0x100c1ce88
DESCRIPTOR_COUNT = 0x118
SUPPORT_TABLE = 0x100cadc50
SUPPORT_BYTES = 64
LE_FEATURES = 0x100cadb2e
FACTORIES = (0x10050a9dc, 0x10050bf00, 0x10050bf48)
REGISTER = 0x100377d28
REGISTERED_CHIP = 0x100c1e994
REGISTERED_CONTEXT = 0x100c2c238
VENDOR_INIT = 0x100377b60
VENDOR_CHIP = 0x100c2b610
VENDOR_OPS = 0x100c2b720
VENDOR_OPS_BYTES = 0xb08
VENDOR_HOOKS = (0x100c2ae40, 0x100c2ae60, 0x100c2aa60, 0x100c2c228)
VENDOR_OPCODES = 0x100c2c230
CALLBACKS = ((0x100377e9c, 0x100377ec0, 0x100377fa8, 0x100c2c278),
             (0x100377fc4, 0x100377fe8, 0x100378098, 0x100c2c428))
OPTIONAL_STEP = 0x100329ec8
CHAIN_NEXT = 0x1003d7848
CHAIN_CONTEXT = 0x100c2a9f0
MODEL_GETTER = 0x1000071f0
MODEL_VTABLE = 0x100bafcf8
# Model slots traced through the target's configuration getters and their logs.
MODEL_CAPABILITIES = dict(ext_adv=0xa30, periodic_adv=0xa38, periodic_sync=0xa40,
    past_sender=0xa48, past_recipient=0xa50, ext_scan=0xac0, enhanced_connection=0xac8,
    spec_adv=0xad8, coded_phy=0xba8, adv_sets=0x1138)
BZERO = 0x10090a160
PACIBSP = 0xd503237f
RET = 0xd65f03c0


def relative(pc, target, bits):
    delta = target - pc
    if delta % 4 or not -(1 << (bits + 1)) <= delta < (1 << (bits + 1)):
        raise ValueError(f'branch outside aligned range: {pc:#x} -> {target:#x}')
    return (delta // 4) & ((1 << bits) - 1)


def branch(pc, target, link=False):
    return (0x94000000 if link else 0x14000000) | relative(pc, target, 26)


def cbnz(pc, reg, target):
    return 0x35000000 | relative(pc, target, 19) << 5 | reg


def adrp(pc, reg, target):
    pages = ((target & ~4095) - (pc & ~4095)) >> 12
    if not -(1 << 20) <= pages < (1 << 20):
        raise ValueError('ADRP outside range')
    pages &= (1 << 21) - 1
    return 0x90000000 | (pages & 3) << 29 | (pages >> 2) << 5 | reg


def add(reg, source, value):
    if not 0 <= value < 4096:
        raise ValueError('ADD immediate outside range')
    return 0x91000000 | value << 10 | source << 5 | reg


def memory(op, reg, base, offset, scale):
    if offset % scale or not 0 <= offset // scale < 4096:
        raise ValueError('load/store offset outside range')
    return op | (offset // scale) << 10 | base << 5 | reg


def mov_w(reg, value):
    if not 0 <= value <= 65535:
        raise ValueError('MOV immediate outside range')
    return 0x52800000 | value << 5 | reg


class NativeImage(_inspect.Image):
    def __init__(self, path):
        super().__init__(path)
        if hashlib.sha256(self.data).hexdigest() != ORIGINAL_SHA256:
            raise ValueError('bluetoothd must match the locked iPadOS 27 original SHA-256')
        if self.uuid != ORIGINAL_UUID or self.subtype != 0x80000002:
            raise ValueError('bluetoothd UUID or arm64e subtype differs')
        self.original = self.data
        self.data = bytearray(self.data)
        self.cursor = CAVE
        self.patches = []
        self.entries = {}
        self.fixups = self.chained_fixups()
        start, end = self.offset(CAVE), self.offset(CAVE_END - 1) + 1
        if any(self.data[start:end]):
            raise ValueError('executable tail is occupied')
        for section in self.sections:
            if max(CAVE, section['address']) < min(CAVE_END, section['address'] + section['size']):
                raise ValueError('executable tail overlaps a section')
        text = next(s for s in self.segments if s[0] == '__TEXT')
        if CAVE_END > text[1] + text[4]:
            raise ValueError('executable tail is not file-backed __TEXT')
        if self.stubs.get('_bzero') != BZERO:
            raise ValueError('bzero import differs')

    def chained_fixups(self):
        """Enumerate the target's dyld USERLAND24 chains without changing them.

        Layout: Apple's mach-o/fixup-chains.h. Authenticated rebases retain
        diversity, address diversity, key and next when their target changes.
        """
        at = 32
        payload = None
        count = struct.unpack_from('<I', self.data, 16)[0]
        for _ in range(count):
            command, size = struct.unpack_from('<II', self.data, at)
            if command == 0x80000034:
                payload, length = struct.unpack_from('<II', self.data, at + 8)
                if payload + length > len(self.data):
                    raise ValueError('chained fixups extend beyond image')
            at += size
        if payload is None:
            raise ValueError('native image has no chained fixups')
        version, starts = struct.unpack_from('<II', self.data, payload)
        if version != 0:
            raise ValueError('unknown chained fixup version')
        starts += payload
        count = struct.unpack_from('<I', self.data, starts)[0]
        if count != len(self.segments):
            raise ValueError('chained fixup segment count differs')
        result = {}
        for index, segment in enumerate(self.segments):
            delta = struct.unpack_from('<I', self.data, starts + 4 + index * 4)[0]
            if not delta:
                continue
            header = starts + delta
            size, page_size, form, offset, _, pages = struct.unpack_from('<IHHQIH', self.data, header)
            if form != 12 or page_size != 16384 or size < 22 + pages * 2:
                raise ValueError('native USERLAND24 page format differs')
            if self.base + offset != segment[1]:
                raise ValueError('chained fixup segment address differs')
            for page in range(pages):
                first = struct.unpack_from('<H', self.data, header + 22 + page * 2)[0]
                if first == 0xffff:
                    continue
                if first & 0x8000 or first >= page_size:
                    raise ValueError('unsupported multi-start native fixup page')
                page_va = self.base + offset + page * page_size
                va = page_va + first
                while True:
                    if va in result or va + 8 > page_va + page_size:
                        raise ValueError('native fixup chain crosses its page')
                    raw = struct.unpack_from('<Q', self.data, self.offset(va))[0]
                    result[va] = raw
                    step = (raw >> 51) & 0x7ff
                    if not step:
                        break
                    va += step * 8
        return result

    def capability_slots(self):
        result = {}
        for name, slot in MODEL_CAPABILITIES.items():
            address = MODEL_VTABLE + slot
            raw = self.fixups.get(address)
            if raw is None or raw >> 62 != 2 or (raw >> 49) & 3 != 0:
                raise ValueError(f'{name} is not an authenticated IA rebase')
            result[name] = dict(slot=hex(slot), address=hex(address),
                                target=hex(self.base + (raw & 0xffffffff)),
                                diversity=hex((raw >> 32) & 65535),
                                address_diversity=bool((raw >> 48) & 1))
        return result

    def put(self, va, words, expected=None):
        if expected is not None:
            actual = [self.word(va + 4 * n) for n in range(len(expected))]
            if actual != expected:
                raise ValueError(f'instruction mismatch at {va:#x}: {actual!r}')
        for n, word in enumerate(words):
            struct.pack_into('<I', self.data, self.offset(va + 4 * n), word)
        if expected is not None:
            self.patches.append(dict(address=hex(va), original=[hex(w) for w in expected],
                                     patched=[hex(w) for w in words]))

    def emit(self, name, words):
        start = self.cursor
        if start + 4 * len(words) > CAVE_END:
            raise ValueError('native trampoline tail exhausted')
        self.put(start, [word(start + n * 4) if callable(word) else word for n, word in enumerate(words)])
        self.cursor += 4 * len(words)
        self.entries[name] = hex(start)
        return start

    def address_words(self, reg, address):
        return [lambda pc: adrp(pc, reg, address), add(reg, reg, address & 4095)]

    def descriptor(self, opcode):
        matches = []
        for index in range(DESCRIPTOR_COUNT):
            va = DESCRIPTORS + index * 24
            op, bits = struct.unpack_from('<HH', self.data, self.offset(va) + 2)
            if op == opcode:
                matches.append((index, bits))
        if len(matches) != 1:
            raise ValueError(f'opcode {opcode:#x} has no unique native descriptor')
        return matches[0]

    def vendor_routing(self):
        for site in FACTORIES:
            self.put(site, [mov_w(1, 0)], [mov_w(1, 15)])
        # Preserve the native bound (1..6000), adding exactly type zero.
        start = self.cursor
        entry = self.emit('registration', [lambda pc: cbnz(pc, 0, start + 8),
            lambda pc: branch(pc, REGISTER + 16), 0x51000409,
            lambda pc: branch(pc, REGISTER + 4)])
        self.put(REGISTER, [branch(REGISTER, entry)], [0x51000409])

        # The original frame and PACIBSP are already in effect. Only type zero
        # skips vendor backend setup. Standard HCI initialization stays native.
        start = self.cursor
        words = [None] + self.address_words(0, VENDOR_OPS) + [mov_w(1, VENDOR_OPS_BYTES),
                  lambda pc: branch(pc, BZERO, True)]
        for address in VENDOR_HOOKS:
            words.extend([lambda pc, a=address: adrp(pc, 8, a),
                          memory(0xf9000000, 31, 8, address & 4095, 8)])
        words.extend([lambda pc: adrp(pc, 8, VENDOR_OPCODES),
                      memory(0xb9000000, 31, 8, VENDOR_OPCODES & 4095, 4),
                      mov_w(0, 0), lambda pc: branch(pc, 0x100377d00)])
        original = start + 4 * len(words)
        words[0] = lambda pc: cbnz(pc, 0, original)
        words.extend([0x51000408, lambda pc: branch(pc, 0x100377b84)])
        entry = self.emit('vendor_init', words)
        self.put(0x100377b80, [branch(0x100377b80, entry)], [0x51000408])

        for n, (_, site, epilogue, _) in enumerate(CALLBACKS):
            start = self.cursor
            entry = self.emit(f'callbacks_{n}', [lambda pc, t=start + 8: cbnz(pc, 8, t),
                lambda pc, t=epilogue: branch(pc, t), 0x51000509,
                lambda pc, t=site + 4: branch(pc, t)])
            self.put(site, [branch(site, entry)], [0x51000509])

        # This optional standard command is absent on some QCA revisions.
        # Use the native support bitmap and real chain-next operation.
        index, bits = self.descriptor(0x0c5b)
        if (index, bits) != (0x7c, 0x1208):
            raise ValueError('optional command descriptor differs')
        byte, mask = bits >> 8, bits & 255
        if byte >= SUPPORT_BYTES or mask != 8:
            raise ValueError('optional command support bit differs')
        address = SUPPORT_TABLE + byte
        start = self.cursor
        entry = self.emit('optional_0c5b', [lambda pc: adrp(pc, 16, address),
            memory(0x39400000, 16, 16, address & 4095, 1),
            lambda pc: 0x36180010 | relative(pc, start + 20, 14) << 5,
            PACIBSP, lambda pc: branch(pc, OPTIONAL_STEP + 4),
            lambda pc: adrp(pc, 8, CHAIN_CONTEXT),
            memory(0xf9400000, 0, 8, CHAIN_CONTEXT & 4095, 8),
            lambda pc: branch(pc, CHAIN_NEXT)])
        self.put(OPTIONAL_STEP, [branch(OPTIONAL_STEP, entry)], [PACIBSP])
        return self

    def report(self):
        return dict(input_sha256=ORIGINAL_SHA256, input_uuid=self.uuid,
                    output_sha256=hashlib.sha256(self.data).hexdigest(),
                    stage='vendor-routing', adapter_ready=False, hardware_verified=False,
                    cave_start=hex(CAVE), cave_end=hex(self.cursor),
                    entries=self.entries, patches=self.patches,
                    capability_slots=self.capability_slots(),
                    pending=['native capability publication', 'H4 shutdown adaptation',
                             'payload installation and device verification'])

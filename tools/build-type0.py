#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Build and sign the version-locked arm64e native capability adapter."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from native_ios27 import layout_header, ORIGINAL_SHA256, ORIGINAL_UUID

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=root/'out/userland')
parser.add_argument('--sdk', type=Path)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
(out/'qbt_ios27_layout.h').write_text(layout_header())
sdk = str(args.sdk or subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'], text=True).strip())
binary = out/'QcaBTType0.dylib'
source = root/'userland/Type0.c'
command = ['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios27.0','-isysroot',sdk,
           '-dynamiclib','-install_name','/usr/lib/QcaBTType0.dylib','-O2','-Wall','-Wextra','-Werror',
           '-fvisibility=hidden','-fstack-protector-strong','-I',str(out),str(source),'-o',str(binary)]
subprocess.run(command, check=True)
subprocess.run(['codesign','--force','--sign','-','--pagesize','4096','--identifier',
                'org.unixnu.bluetooth.Type0',str(binary)], check=True)
subprocess.run(['codesign','--verify','--strict',str(binary)], check=True)
detail = subprocess.run(['codesign','--display','--verbose=4',str(binary)],text=True,capture_output=True,check=True).stderr
cdhash = re.search(r'^CDHash=([0-9a-f]{40})$',detail,re.M)
if not cdhash:raise SystemExit('Native library has no CDHash')
report = dict(built=True,target='arm64e-apple-ios27.0',hardware_verified=False,
              native_input_sha256=ORIGINAL_SHA256,native_uuid=ORIGINAL_UUID,cdhash=cdhash[1],command=command,
              inputs={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                      [source,root/'tools/native_ios27.py']},
              files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [binary,out/'qbt_ios27_layout.h']})
(out/'type0-report.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'Built signed arm64e native capability adapter: {binary}; CDHash {cdhash[1]}')

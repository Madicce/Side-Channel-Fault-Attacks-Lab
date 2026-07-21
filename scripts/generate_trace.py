from rainbow.devices import rainbow_stm32f215
import rainbow
import h5py

# e = rainbow_stm32f215()
# print("create emulator")
# e.load("../SRC/AES/aes.elf", typ=".elf")
# print("charge elf file")
# e.reset()
# print("reset emulator")
# e.start(0x08000000)

# Standard scientific Python stack
import sys
from os import path
import os
import random
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
import struct

# HoloViews + Bokeh are used from Section 4 onward for interactive overlays
# import holoviews as hv
# hv.extension('bokeh', inline=True)
# from bokeh.plotting import show

# Output directory for saved traces
OUTPUT_DIR = Path('data')
OUTPUT_DIR.mkdir(exist_ok=True)

WAVEFORM_DIR = Path('ACQUISITION/waveform')
WAVEFORM_DIR.mkdir(exist_ok=True)

np.random.seed(42)

plt.rcParams.update({
    'figure.figsize':    (14, 4),
    'figure.dpi':        110,
    'axes.spines.top':   False,
    'axes.spines.right': False,
})

print('All imports OK')

# ── ELF binary path check ─────────────────────────────────────────────────────
# The ELF file is the compiled ARM binary for the STM32F215 target.
# It must be compiled from RCS/firmware/ before running this lab.
# If the path below is wrong, adjust it to where your .elf file lives.

ELF_PATH = Path('./SRC/AES/aes.elf')

if not ELF_PATH.exists():
    print(f'WARNING: ELF not found at {ELF_PATH}')
    print('Run: make build-elf from the repo root')
else:
    print(f'ELF found: {ELF_PATH}  ({ELF_PATH.stat().st_size:,} bytes)')

# from rainbow.generics import rainbow_stm32f215
# The ELF symbols are loaded so we can call functions by name
# emulator = rainbow_stm32f215(trace_config=rainbow.TraceConfig(register=rainbow.HammingWeight())) 
emulator = rainbow_stm32f215() 
emulator.load(str(ELF_PATH))
emulator.reset()
print('Emulator loaded successfully')
print(f'Number of symbols (functions/variables) found: {len(emulator.functions)}')

# ── Inspect the available functions in the binary ────────────────────────────
# emulator.functions is a dict: { function_name: address }
# This shows us what we can call inside the firmware.

print('Functions found in the ELF:')
for function_name, address in sorted(emulator.functions.items()):
    print(f'  0x{address[0]:08x}  {function_name}')

# print('Symbols export found in ELF:')
# print(emulator.symbols.keys())

from unicorn import UC_HOOK_CODE

from unicorn.arm_const import *

REGS = [
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
]

old_regs = {}

INV_START = emulator.functions['aes_encrypt'][0] & ~1 
tracing = False
my_trace = []
return_addr = 0

def hw(x):
    return bin(x & 0xffffffff).count("1")

for reg in REGS:
    old_regs[reg] = 0

def hook_code(uc, address, size, user_data):
    global tracing
    global return_addr
    global my_trace

    pc = address & ~1

    if pc == INV_START:
        tracing = True
        return_addr = uc.reg_read(UC_ARM_REG_LR) & ~1
    
    if tracing:
        for reg in REGS:
            new = uc.reg_read(reg)
            if new != old_regs[reg]:
                my_trace.append(hw(new))

            old_regs[reg] = new

    if tracing and pc == return_addr:
        tracing = False

emulator.emu.hook_add(UC_HOOK_CODE, hook_code)

# ── Memory layout for our ECDSA calls ─────────────────────────────────────────
# We need to place key, plaintext and output buffer somewhere in RAM.
ADDR_STATE  = 0xCAFE_0000
ADDR_KEY    = 0xCAFE_1000
ADDR_RETURN = 0xDEAD_0000

# ── Helper function: run one ECDSA signature and collect a trace ──────────
# We will use this function throughout the rest of the lab.
def run_aes_stm32(state: int, key: int):
    """
    Run AES-128 on the emulated STM32F215 and return (ciphertext, power_trace).

    Steps:
      1. Write key and plaintext into emulated RAM
      2. Reset the emulator's trace buffer
      3. Call the AES function by name (the ELF symbol)
      4. Read back the ciphertext from the output buffer
      5. Return the power trace recorded during execution
    """
    emulator.reset()
    emulator[ADDR_STATE]  = state
    # emulator[ADDR_SIGNATURE] = bytes([0] * 2)
    emulator[ADDR_KEY] = key
    emulator['r0'] = ADDR_STATE
    emulator['r1'] = ADDR_KEY
    emulator['lr'] = ADDR_RETURN | 1
    emulator.start(emulator.functions['aes_encrypt_init'][0] , ADDR_RETURN)
    # emulator.trace is a list of dicts: [{'register': hw_value}, ...]
    # Extract the 'register' key from each event or 'memory' key if it's wanted
    ciphertext = emulator.emu.mem_read(ADDR_STATE, 8)
    trace = np.array(
        [event['register'] for event in emulator.trace if 'register' in event],
        dtype=np.float32
    )
    return ciphertext, trace

print('run_aes_stm32 defined')

# ── Run one AES and verify correctness ───────────────────────────────────────

STATE = bytes([
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
])

KEY = bytes([
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
])

# FIX AES
for i in range(100):
    _, trace = run_aes_stm32(STATE, KEY)
    with h5py.File(WAVEFORM_DIR / f"fix_{i}.h5", "w") as f:
        f.create_dataset(
            "trace",
            data=trace
        )

        f.create_dataset(
            "plaintext",
            data=list(STATE)
        )

        f.create_dataset(
            "key",
            data=list(KEY)
        )

# VARIABLE AES
for j in range(100):
    random_state = os.urandom(16)

    _, trace = run_aes_stm32(random_state, KEY)

    with h5py.File(WAVEFORM_DIR / f"var_{j}.h5", "w") as f:
        f.create_dataset(
            "trace",
            data=trace
        )

        f.create_dataset(
            "plaintext",
            data=list(random_state)
        )

        f.create_dataset(
            "key",
            data=list(KEY)
        )

# print(f'Expected ciphertext  : {reference_ciphertext}')
# print(f'Match                : {emulated_ciphertext == reference_ciphertext}')
# print()
# print(f'Lab 0 aes.py trace length  : 640 samples   (one per AES state byte write)')
# print(f'Emulator trace length      : {len(first_trace)} samples   (one per ARM instruction)')
# print(f'Ratio                      : {len(first_trace) / 640:.1f}x more samples')
# print()
# print('Each of those extra samples is an individual ARM instruction.')

# ── Plot the first trace ──────────────────────────────────────────────────────
# This is the raw power trace of one AES-128 encryption on the STM32F215.
# You should see a repeating structure (10 rounds of AES).

# fig, ax = plt.subplots(figsize=(16, 4))
# ax.plot(first_trace, color='steelblue', linewidth=0.5)
# ax.set_xlabel('Sample index (one sample = one ARM instruction)')
# ax.set_ylabel('HW of written register value')
# ax.set_title('First emulated AES-128 trace — 10 AES rounds visible as repeating structure')
# ax.set_ylim(-0.5, 32.5)
# plt.tight_layout()
# plt.savefig(OUTPUT_DIR / 'Lab1_first_trace.png', dpi=150)
# plt.show()

# plt.show(moving_mean(first_trace, 50))

# print('The repeating blocks of ~N samples correspond to the 10 AES rounds.')

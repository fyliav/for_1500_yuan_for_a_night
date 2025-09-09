from keystone import *

ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
ks.asm("nop", 0, True)

from argparse import ArgumentParser
import logging
import os
import re

from elfesteem import elf as elf_csts

from miasm2.os_dep.linux.environment import LinuxEnvironment_x86_64, AuxVec, \
    prepare_loader_stack_x86_64
from miasm2.os_dep.linux.syscall import enable_syscall_handling, log, \
    syscall_callbacks_x86_64
from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container

parser = ArgumentParser("Run an ELF in a Linux-like environment")
parser.add_argument("target", help="Target ELF")
parser.add_argument("extra_args", help="Arguments for the target ELF",
                    nargs="*", default=[])
parser.add_argument("-j", "--jitter", help="Jitter engine", default="llvm")
parser.add_argument("-p", "--passthrough", help="Reg-exp for passthrough files",
                    default="^$")
parser.add_argument("-f", "--flags", help="Flags")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Activate verbose syscalls")
args = parser.parse_args()

if args.verbose:
    log.setLevel(logging.DEBUG)

# Get corresponding interpreter and reloc address
cont_target_tmp = Container.from_stream(open(args.target))
ld_path = str(cont_target_tmp.executable.getsectionbyname(".interp").content).strip("\x00")
if cont_target_tmp.executable.Ehdr.type in [elf_csts.ET_REL, elf_csts.ET_DYN]:
    elf_base_addr = 0x40000000
elif cont_target_tmp.executable.Ehdr.type == elf_csts.ET_EXEC:
    elf_base_addr = 0 # Not relocatable
else:
    raise ValueError("Unsuported type %d" % cont_target_tmp.executable.Ehdr.type)

# Instanciate a jitter
machine = Machine(cont_target_tmp.arch)
if cont_target_tmp.arch != "x86_64":
    raise ValueError("Only x86_64 environment are handled")
jitter = machine.jitter(args.jitter)
jitter.init_stack()

# Load the interpreter in memory, applying relocation
linux_env = LinuxEnvironment_x86_64()
linux_env.filesystem.passthrough.append(re.compile(args.passthrough))
ld_path = linux_env.filesystem.resolve_path(ld_path)
cont_ld = Container.from_stream(open(ld_path),
                                vm=jitter.vm,
                                addr=0x80000000,
                                apply_reloc=True)
# Load the target ELF in memory, without applying reloc
loc_db = cont_ld.loc_db
cont_target = Container.from_stream(open(args.target), vm=jitter.vm,
                                    loc_db=loc_db,
                                    addr=elf_base_addr,
                                    apply_reloc=False)
# PHDR containing the PH header
elf_phdr_header = [ph64.ph for ph64 in cont_target.executable.ph
                   if ph64.ph.type == elf_csts.PT_PHDR][0]

# Prepare the desired environment
argv = [args.target] + args.extra_args
if args.flags:
    argv += ["-%s" % args.flags]
envp = {"PATH": "/usr/local/bin", "USER": linux_env.user_name}
auxv = AuxVec(elf_base_addr + elf_phdr_header.vaddr, cont_target.entry_point,
              linux_env)
prepare_loader_stack_x86_64(jitter, argv, envp, auxv)
enable_syscall_handling(jitter, linux_env, syscall_callbacks_x86_64)

# Run
jitter.init_run(cont_ld.entry_point)
jitter.continue_run()

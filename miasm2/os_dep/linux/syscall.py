import fcntl
import functools
import logging
import os
import struct
import termios

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_PRIV_INSN
from miasm2.core.interval import interval
from miasm2.os_dep.linux.environment import FileDescriptorDirectory

log = logging.getLogger('syscalls')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.WARNING)


def _dump_struct_stat_x86_64(info):
    data = struct.pack("QQQIIIIQQQQQQQQQQQQQ",
                       info.st_dev,
                       info.st_ino,
                       info.st_nlink,
                       info.st_mode,
                       info.st_uid,
                       info.st_gid,
                       0, # 32 bit padding
                       info.st_rdev,
                       info.st_size,
                       info.st_blksize,
                       info.st_blocks,
                       info.st_atime,
                       info.st_atimensec,
                       info.st_mtime,
                       info.st_mtimensec,
                       info.st_ctime,
                       info.st_ctimensec,
                       0, # unused
                       0, # unused
                       0, # unused
    )
    return data


def sys_x86_64_rt_sigaction(jitter, linux_env):
    # Parse arguments
    sig = jitter.cpu.RDI
    act = jitter.cpu.RSI
    oact = jitter.cpu.RDX
    sigsetsize = jitter.cpu.R10
    log.debug("sys_rt_sigaction(%x, %x, %x, %x)", sig, act, oact, sigsetsize)

    # Stub
    if oact != 0:
        # Return an empty old action
        jitter.vm.set_mem(oact, "\x00" * sigsetsize)
    jitter.cpu.RAX = 0


def sys_x86_64_brk(jitter, linux_env):
    # Parse arguments
    addr = jitter.cpu.RDI
    log.debug("sys_brk(%d)", addr)

    # Stub
    if addr == 0:
        jitter.cpu.RAX = linux_env.brk_current
    else:
        all_mem = jitter.vm.get_all_memory()
        mapped = interval([(start, start + info["size"] - 1)
                           for start, info in all_mem.iteritems()])

        # Alloc missing and override
        missing = interval([(linux_env.brk_current, addr)]) - mapped
        for start, stop in missing:
            jitter.vm.add_memory_page(start, PAGE_READ|PAGE_WRITE,
                                      "\x00" * (stop - start + 1),
                                      "BRK")

        linux_env.brk_current = addr
        jitter.cpu.RAX = linux_env.brk_current


def sys_x86_64_newuname(jitter, linux_env):
    # struct utsname {
    #     char sysname[];    /* Operating system name (e.g., "Linux") */
    #     char nodename[];   /* Name within "some implementation-defined
    #                            network" */
    #     char release[];    /* Operating system release (e.g., "2.6.28") */
    #     char version[];    /* Operating system version */
    #     char machine[];    /* Hardware identifier */
    # }

    # Parse arguments
    nameptr = jitter.cpu.RDI
    log.debug("sys_newuname(%x)", nameptr)

    # Stub
    info = [
        linux_env.sys_sysname,
        linux_env.sys_nodename,
        linux_env.sys_release,
        linux_env.sys_version,
        linux_env.sys_machine
    ]
    # TODO: Elements start at 0x41 multiples on my tests...
    output = ""
    for elem in info:
        output += elem
        output += "\x00" * (0x41 - len(elem))
    jitter.vm.set_mem(nameptr, output)
    jitter.cpu.RAX = 0


def sys_x86_64_access(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    mode = jitter.cpu.RDX
    rpathname = jitter.get_str_ansi(pathname)
    rmode = mode
    if mode == 1:
        rmode = "F_OK"
    elif mode == 2:
        rmode = "R_OK"
    log.debug("sys_access(%s, %s)", rpathname, rmode)

    # Stub
    # Do not check the mode
    if linux_env.filesystem.exists(rpathname):
        jitter.cpu.RAX = 0
    else:
        jitter.cpu.RAX = -1


def sys_x86_64_openat(jitter, linux_env):
    # Parse arguments
    dfd = jitter.cpu.RDI
    filename = jitter.cpu.RSI
    flags = jitter.cpu.RDX
    mode = jitter.cpu.R10
    rpathname = jitter.get_str_ansi(filename)
    log.debug("sys_openat(%x, %r, %x, %x)", dfd, rpathname, flags, mode)

    # Stub
    # mode, flags, etc. are ignored
    jitter.cpu.RAX = linux_env.open_(rpathname, flags)


def sys_x86_64_newstat(jitter, linux_env):
    # Parse arguments
    filename = jitter.cpu.RDI
    statbuf = jitter.cpu.RSI
    rpathname = jitter.get_str_ansi(filename)
    log.debug("sys_newstat(%r, %x)", rpathname, statbuf)

    # Stub
    if linux_env.filesystem.exists(rpathname):
        info = linux_env.stat(rpathname)
        data = _dump_struct_stat_x86_64(info)
        jitter.vm.set_mem(statbuf, data)
        jitter.cpu.RAX = 0
    else:
        # ENOENT (No such file or directory)
        jitter.cpu.RAX = -1


def sys_x86_64_writev(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    vlen = jitter.cpu.RDX
    vec = jitter.cpu.RSI
    log.debug("sys_writev(%d, %d, %x)", fd, vlen, vec)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    for iovec_num in xrange(vlen):
        # struct iovec {
        #    void  *iov_base;    /* Starting address */
        #    size_t iov_len;     /* Number of bytes to transfer */
        # };
        iovec = jitter.vm.get_mem(vec + iovec_num * 8 * 2, 8*2)
        iov_base, iov_len = struct.unpack("QQ", iovec)
        fdesc.write(jitter.get_str_ansi(iov_base)[:iov_len])

    jitter.cpu.RAX = vlen


def sys_x86_64_exit_group(jitter, linux_env):
    # Parse arguments
    status = jitter.cpu.RDI
    log.debug("sys_exit_group(%d)", status)

    # Stub
    log.debug("Exit with status code %d", status)
    jitter.run = False


def sys_x86_64_read(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    count = jitter.cpu.RDX
    log.debug("sys_read(%d, %x, %x)", fd, buf, count)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    data = fdesc.read(count)
    jitter.cpu.RAX = len(data)
    jitter.vm.set_mem(buf, data)


def sys_x86_64_fstat(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    statbuf = jitter.cpu.RSI
    log.debug("sys_fstat(%d, %x)", fd, statbuf)

    # Stub
    info = linux_env.fstat(fd)
    data = _dump_struct_stat_x86_64(info)
    jitter.vm.set_mem(statbuf, data)
    jitter.cpu.RAX = 0


def sys_x86_64_mmap(jitter, linux_env):
    # Parse arguments
    addr = jitter.cpu.RDI
    len_ = jitter.cpu.RSI
    prot = jitter.cpu.RDX & 0xFFFFFFFF
    flags = jitter.cpu.R10 & 0xFFFFFFFF
    fd = jitter.cpu.R8 & 0xFFFFFFFF
    off = jitter.cpu.R9
    log.debug("sys_mmap(%x, %x, %x, %x, %x, %x)", addr, len_, prot, flags, fd, off)

    # Stub
    if addr == 0:
        addr = linux_env.mmap_current
        linux_env.mmap_current += (len_ + 0x1000) & ~0xfff

    all_mem = jitter.vm.get_all_memory()
    mapped = interval([(start, start + info["size"] - 1)
                       for start, info in all_mem.iteritems()])

    MAP_FIXED = 0x10
    if flags & MAP_FIXED:
        # Alloc missing and override
        missing = interval([(addr, addr + len_ - 1)]) - mapped
        for start, stop in missing:
            jitter.vm.add_memory_page(start, PAGE_READ|PAGE_WRITE,
                                      "\x00" * (stop - start + 1),
                                      "mmap allocated")
    else:
        # Find first candidate segment nearby addr
        for start, stop in mapped:
            if stop < addr:
                continue
            rounded = (stop + 1 + 0x1000) & ~0xfff
            if (interval([(rounded, rounded + len_)]) & mapped).empty:
                addr = rounded
                break
        else:
            assert (interval([(addr, addr + len_)]) & mapped).empty

        jitter.vm.add_memory_page(addr, PAGE_READ|PAGE_WRITE, "\x00" * len_,
                                  "mmap allocated")


    if fd == 0xffffffff:
        if off != 0:
            raise RuntimeError("Not implemented")
        data = "\x00" * len_
    else:
        fdesc = linux_env.file_descriptors[fd]
        cur_pos = fdesc.tell()
        fdesc.seek(off)
        data = fdesc.read(len_)
        fdesc.seek(cur_pos)

    jitter.vm.set_mem(addr, data)
    jitter.cpu.RAX = addr


def sys_x86_64_mprotect(jitter, linux_env):
    # Parse arguments
    start = jitter.cpu.RDI
    len_ = jitter.cpu.RSI
    prot = jitter.cpu.RDX
    assert jitter.vm.is_mapped(start, len_)
    log.debug("sys_mprotect(%x, %x, %x)", start, len_, prot)

    # Do nothing
    jitter.cpu.RAX = 0

def sys_x86_64_close(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    log.debug("sys_close(%x)", fd)

    fdesc = linux_env.file_descriptors[fd]
    fdesc.close()
    jitter.cpu.RAX = 0


def sys_x86_64_arch_prctl(jitter, linux_env):
    # Parse arguments
    code_name = {
        0x1001: "ARCH_SET_GS",
        0x1002: "ARCH_SET_FS",
        0x1003: "ARCH_GET_FS",
        0x1004: "ARCH_GET_GS",
    }
    code = jitter.cpu.RDI
    rcode = code_name[code]
    addr = jitter.cpu.RSI
    log.debug("sys_arch_prctl(%s, %x)", rcode, addr)

    if code == 0x1002:
        jitter.cpu.set_segm_base(jitter.cpu.FS, addr)
    else:
        raise RuntimeError("Not implemented")
    jitter.cpu.RAX = 0


def sys_x86_64_set_tid_address(jitter, linux_env):
    # Parse arguments
    tidptr = jitter.cpu.RDI
    # clear_child_tid = tidptr
    log.debug("sys_set_tid_address(%x)", tidptr)

    jitter.cpu.RAX = linux_env.process_tid


def sys_x86_64_set_robust_list(jitter, linux_env):
    # Parse arguments
    head = jitter.cpu.RDI
    len_ = jitter.cpu.RSI
    # robust_list = head
    log.debug("sys_set_robust_list(%x, %x)", head, len_)
    jitter.cpu.RAX = 0

def sys_x86_64_rt_sigprocmask(jitter, linux_env):
    # Parse arguments
    how = jitter.cpu.RDI
    nset = jitter.cpu.RSI
    oset = jitter.cpu.RDX
    sigsetsize = jitter.cpu.R10
    log.debug("sys_rt_sigprocmask(%x, %x, %x, %x)", how, nset, oset, sigsetsize)
    if oset != 0:
        raise RuntimeError("Not implemented")
    jitter.cpu.RAX = 0


def sys_x86_64_prlimit64(jitter, linux_env):
    # Parse arguments
    pid = jitter.cpu.RDI
    resource = jitter.cpu.RSI
    new_rlim = jitter.cpu.RDX
    if new_rlim != 0:
        raise RuntimeError("Not implemented")
    old_rlim = jitter.cpu.R10
    log.debug("sys_prlimit64(%x, %x, %x, %x)", pid, resource, new_rlim,
              old_rlim)

    # Stub
    if resource == 3:
        # RLIMIT_STACK
        jitter.vm.set_mem(old_rlim,
                          struct.pack("QQ",
                                      0x100000,
                                      0x7fffffffffffffff, # RLIM64_INFINITY
                          ))
    else:
        raise RuntimeError("Not implemented")
    jitter.cpu.RAX = 0


def sys_x86_64_statfs(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    rpathname = jitter.get_str_ansi(pathname)
    log.debug("sys_statfs(%r, %x)", rpathname, buf)

    # Stub
    if not linux_env.filesystem.exists(rpathname):
        jitter.cpu.RAX = -1
    else:
        info = linux_env.filesystem.statfs()
        raise RuntimeError("Not implemented")


def sys_x86_64_ioctl(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    cmd = jitter.cpu.RSI
    arg = jitter.cpu.RDX
    log.debug("sys_ioctl(%x, %x, %x)", fd, cmd, arg)

    allowed = False
    disallowed = False
    for test in [(fd, cmd), (None, cmd), (fd, None)]:
        if test in linux_env.ioctl_allowed:
            allowed = True
        if test in linux_env.ioctl_disallowed:
            disallowed = True

    if allowed and disallowed:
        raise ValueError("fd: %x, cmd: %x is allowed and disallowed" % (fd, cmd))

    if allowed:
        if cmd == termios.TCGETS:
            data = "\x00" * 4
        elif cmd == termios.TIOCGWINSZ:
            # struct winsize
            # {
            #   unsigned short ws_row;	/* rows, in characters */
            #   unsigned short ws_col;	/* columns, in characters */
            #   unsigned short ws_xpixel;	/* horizontal size, pixels */
            #   unsigned short ws_ypixel;	/* vertical size, pixels */
            # };
            data = struct.pack("HHHH", 1000, 360, 1000, 1000)
        elif cmd == termios.TIOCSWINSZ:
            # Do nothing
            pass
        else:
            raise RuntimeError("Not implemented")

        jitter.vm.set_mem(arg, data)
        jitter.cpu.RAX = 0

    elif disallowed:
        jitter.cpu.RAX = -1

    else:
        raise KeyError("Unknown ioctl fd:%x cmd:%x" % (fd, cmd))


def sys_x86_64_open(jitter, linux_env):
    # Parse arguments
    filename = jitter.cpu.RDI
    flags = jitter.cpu.RSI
    mode = jitter.cpu.RDX
    rpathname = jitter.get_str_ansi(filename)
    log.debug("sys_open(%r, %x, %x)", rpathname, flags, mode)

    # Stub
    # mode, flags, etc. are ignored
    jitter.cpu.RAX = linux_env.open_(rpathname, flags)


def sys_x86_64_write(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    count = jitter.cpu.RDX
    buf = jitter.cpu.RSI
    log.debug("sys_write(%d, %d, %x)", fd, count, buf)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    data = jitter.vm.get_mem(buf, count)
    fdesc.write(data)
    jitter.cpu.RAX = count


def sys_x86_64_getdents(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    dirent = jitter.cpu.RSI
    count = jitter.cpu.RDX
    log.debug("sys_getdents(%x, %x, %x)", fd, dirent, count)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    if not isinstance(fdesc, FileDescriptorDirectory):
        raise RuntimeError("Not implemented")


    out = ""
    # fdesc.listdir continues from where it stopped
    for name in fdesc.listdir():
        # struct dirent
        # {
        #     __ino_t d_ino; /* Inode number */
        #     __off_t d_off; /* Offset to next dirent */
        #     unsigned short int d_reclen; /* Length of this linux_dirent */
        #     unsigned char d_type; /* File type */
        #     char d_name[256]; /* filename */
        # };

        d_ino = 1 # Not the real one
        d_reclen = 8 * 2 + 2 + 1 + len(name) + 1
        d_off = len(out) + d_reclen
        d_type = 0 # Not the real one
        entry = struct.pack("QqH", d_ino, d_off, d_reclen) + \
                name + "\x00" + struct.pack("B", d_type)
        assert len(entry) == d_reclen

        if len(out) + len(entry) > count:
            # Report to a further call
            fdesc.cur_listdir.append(name)
            break
        out = out + entry

    jitter.vm.set_mem(dirent, out)
    jitter.cpu.RAX = len(out)


def sys_x86_64_newlstat(jitter, linux_env):
    # Parse arguments
    filename = jitter.cpu.RDI
    statbuf = jitter.cpu.RSI
    rpathname = jitter.get_str_ansi(filename)
    log.debug("sys_newlstat(%s, %x)", rpathname, statbuf)

    # Stub
    if not linux_env.filesystem.exists(rpathname):
        # ENOENT (No such file or directory)
        jitter.cpu.RAX = -1
    else:
        info = linux_env.lstat(rpathname)
        data = _dump_struct_stat_x86_64(info)
        jitter.vm.set_mem(statbuf, data)
        jitter.cpu.RAX = 0


def sys_x86_64_lgetxattr(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    name = jitter.cpu.RSI
    value = jitter.cpu.RDX
    size = jitter.cpu.R10
    rpathname = jitter.get_str_ansi(pathname)
    rname = jitter.get_str_ansi(name)
    log.debug("sys_lgetxattr(%r, %r, %x, %x)", rpathname, rname, value, size)

    # Stub
    jitter.vm.set_mem(value, "\x00" * size)
    jitter.cpu.RAX = 0


def sys_x86_64_getxattr(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    name = jitter.cpu.RSI
    value = jitter.cpu.RDX
    size = jitter.cpu.R10
    rpathname = jitter.get_str_ansi(pathname)
    rname = jitter.get_str_ansi(name)
    log.debug("sys_getxattr(%r, %r, %x, %x)", rpathname, rname, value, size)

    # Stub
    jitter.vm.set_mem(value, "\x00" * size)
    jitter.cpu.RAX = 0


def sys_x86_64_socket(jitter, linux_env):
    # Parse arguments
    family = jitter.cpu.RDI
    type_ = jitter.cpu.RSI
    protocol = jitter.cpu.RDX
    log.debug("sys_socket(%x, %x, %x)", family, type_, protocol)

    jitter.cpu.RAX = linux_env.socket(family, type_, protocol)


def sys_x86_64_connect(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    uservaddr = jitter.cpu.RSI
    addrlen = jitter.cpu.RDX
    raddr = jitter.get_str_ansi(uservaddr + 2)
    log.debug("sys_connect(%x, %r, %x)", fd, raddr, addrlen)

    # Stub
    # Always refuse the connexion
    jitter.cpu.RAX = -1


def sys_x86_64_clock_gettime(jitter, linux_env):
    # Parse arguments
    which_clock = jitter.cpu.RDI
    tp = jitter.cpu.RSI
    log.debug("sys_clock_gettime(%x, %x)", which_clock, tp)

    # Stub
    value = linux_env.clock_gettime()
    jitter.vm.set_mem(tp, struct.pack("Q", value))
    jitter.cpu.RAX = 0


def sys_x86_64_lseek(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    offset = jitter.cpu.RSI
    whence = jitter.cpu.RDX
    log.debug("sys_lseek(%d, %x, %x)", fd, offset, whence)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    mask = (1 << 64) - 1
    if offset > (1 << 63):
        offset = - ((offset ^ mask) + 1)

    new_offset = fdesc.lseek(offset, whence)
    jitter.cpu.RAX = new_offset


def sys_x86_64_munmap(jitter, linux_env):
    # Parse arguments
    addr = jitter.cpu.RDI
    len_ = jitter.cpu.RSI
    log.debug("sys_munmap(%x, %x)", addr, len_)

    # Do nothing
    jitter.cpu.RAX = 0


def sys_x86_64_readlink(jitter, linux_env):
    # Parse arguments
    path = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    bufsize = jitter.cpu.RDX
    rpath = jitter.get_str_ansi(path)
    log.debug("sys_readlink(%r, %x, %x)", rpath, buf, bufsize)

    # Stub
    link = linux_env.filesystem.readlink(rpath)
    if link is None:
        # Not a link
        jitter.cpu.RAX = -1
    else:
        data = link[:bufsize - 1] + "\x00"
        jitter.vm.set_mem(buf, data)
        jitter.cpu.RAX = len(data) - 1

def sys_x86_64_getpid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getpid()")

    # Stub
    jitter.cpu.RAX = linux_env.process_pid


def sys_x86_64_sysinfo(jitter, linux_env):
    # Parse arguments
    info = jitter.cpu.RDI
    log.debug("sys_sysinfo(%x)", info)

    # Stub
    data = struct.pack("QQQQQQQQQQHQQI",
                       0x1234, # uptime
                       0x2000, # loads (1 min)
                       0x2000, # loads (5 min)
                       0x2000, # loads (15 min)
                       0x10000000, # total ram
                       0x10000000, # free ram
                       0x10000000, # shared memory
                       0x0, # memory used by buffers
                       0x0, # total swap
                       0x0, # free swap
                       0x1, # nb current processes
                       0x0, # total high mem
                       0x0, # available high mem
                       0x1, # memory unit size
    )
    jitter.vm.set_mem(info, data)
    jitter.cpu.RAX = 0


def sys_x86_64_geteuid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_geteuid()")

    # Stub
    jitter.cpu.RAX = linux_env.user_euid


def sys_x86_64_getegid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getegid()")

    # Stub
    jitter.cpu.RAX = linux_env.user_egid


def sys_x86_64_getuid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getuid()")

    # Stub
    jitter.cpu.RAX = linux_env.user_uid


def sys_x86_64_getgid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getgid()")

    # Stub
    jitter.cpu.RAX = linux_env.user_gid


def sys_x86_64_fcntl(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    cmd = jitter.cpu.RSI
    arg = jitter.cpu.RDX
    log.debug("sys_fcntl(%x, %x, %x)", fd, cmd, arg)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    if cmd == fcntl.F_GETFL:
        jitter.cpu.RAX = fdesc.flags
    elif cmd == fcntl.F_SETFL:
        # Ignore flag change
        jitter.cpu.RAX = 0
    else:
        raise RuntimeError("Not implemented")


def sys_x86_64_pread64(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    count = jitter.cpu.RDX
    pos = jitter.cpu.R10
    log.debug("sys_pread64(%x, %x, %x, %x)", fd, buf, count, pos)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    cur_pos = fdesc.tell()
    fdesc.seek(pos)
    data = fdesc.read(count)
    jitter.vm.set_mem(buf, data)
    fdesc.seek(cur_pos)
    jitter.cpu.RAX = len(data)


syscall_callbacks_x86_64 = {
    0x0: sys_x86_64_read,
    0x1: sys_x86_64_write,
    0x2: sys_x86_64_open,
    0x3: sys_x86_64_close,
    0x4: sys_x86_64_newstat,
    0x5: sys_x86_64_fstat,
    0x6: sys_x86_64_newlstat,
    0x8: sys_x86_64_lseek,
    0x9: sys_x86_64_mmap,
    0x10: sys_x86_64_ioctl,
    0xA: sys_x86_64_mprotect,
    0xB: sys_x86_64_munmap,
    0xC: sys_x86_64_brk,
    0xD: sys_x86_64_rt_sigaction,
    0xE: sys_x86_64_rt_sigprocmask,
    0x11: sys_x86_64_pread64,
    0x14: sys_x86_64_writev,
    0x15: sys_x86_64_access,
    0x27: sys_x86_64_getpid,
    0x29: sys_x86_64_socket,
    0x2A: sys_x86_64_connect,
    0x3F: sys_x86_64_newuname,
    0x48: sys_x86_64_fcntl,
    0x4E: sys_x86_64_getdents,
    0x59: sys_x86_64_readlink,
    0x63: sys_x86_64_sysinfo,
    0x66: sys_x86_64_getuid,
    0x68: sys_x86_64_getgid,
    0x6B: sys_x86_64_geteuid,
    0x6C: sys_x86_64_getegid,
    0xE4: sys_x86_64_clock_gettime,
    0x89: sys_x86_64_statfs,
    0x9E: sys_x86_64_arch_prctl,
    0xBF: sys_x86_64_getxattr,
    0xC0: sys_x86_64_lgetxattr,
    0xDA: sys_x86_64_set_tid_address,
    0xE7: sys_x86_64_exit_group,
    0x101: sys_x86_64_openat,
    0x111: sys_x86_64_set_robust_list,
    0x12E: sys_x86_64_prlimit64,
}


def syscall_x86_64_exception_handler(linux_env, syscall_callbacks, jitter):
    """Call to actually handle an EXCEPT_PRIV_INSN exception
    In the case of an error raised by a SYSCALL, call the corresponding
    syscall_callbacks
    @linux_env: LinuxEnvironment_x86_64 instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)
    """
    # Ensure the jitter has break on a SYSCALL
    cur_instr = jitter.jit.mdis.dis_instr(jitter.pc)
    if cur_instr.name != "SYSCALL":
        return True

    # Dispatch to SYSCALL stub
    syscall_number = jitter.cpu.RAX
    callback = syscall_callbacks.get(syscall_number)
    if callback is None:
        raise KeyError(
            "No callback found for syscall number 0x%x" % syscall_number
        )
    callback(jitter, linux_env)
    log.debug("-> %x", jitter.cpu.RAX)

    # Clean exception and move pc to the next instruction, to let the jitter
    # continue
    jitter.cpu.set_exception(jitter.cpu.get_exception() ^ EXCEPT_PRIV_INSN)
    jitter.pc += cur_instr.l
    return True


def enable_syscall_handling(jitter, linux_env, syscall_callbacks):
    """Activate handling of syscall for the current jitter instance.
    Syscall handlers are provided by @syscall_callbacks
    @linux_env: LinuxEnvironment instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)

    Example of use:
    >>> linux_env = LinuxEnvironment_x86_64()
    >>> enable_syscall_handling(jitter, linux_env, syscall_callbacks_x86_64)
    """
    arch_name = jitter.jit.arch_name
    if arch_name == "x8664":
        handler = syscall_x86_64_exception_handler
    else:
        raise ValueError("No syscall handler implemented for %s" % arch_name)

    handler = functools.partial(handler, linux_env, syscall_callbacks)
    jitter.add_exception_handler(EXCEPT_PRIV_INSN, handler)

from collections import namedtuple
import os
import termios


StatInfo = namedtuple("StatInfo", [
    "st_dev", "st_ino", "st_nlink", "st_mode", "st_uid", "st_gid", "st_rdev",
    "st_size", "st_blksize", "st_blocks", "st_atime", "st_atimensec",
    "st_mtime", "st_mtimensec", "st_ctime", "st_ctimensec"
])
StatFSInfo = namedtuple("StatFSInfo", [
    "f_type", "f_bsize", "f_blocks", "f_bfree", "f_bavail", "f_files",
    "f_ffree", "f_fsid", "f_namelen", "f_frsize", "f_flags", "f_spare",
])


class FileDescriptor(object):
    """Stand for a file descriptor on a system

    According to inode(7), following types are possibles:
     - socket
     - symbolic link
     - regular file
     - block device
     - directory
     - character device
     - FIFO
    """

    # st_mode's file type
    file_type = None
    # st_mode's file mode (9 least bits are file permission bits)
    file_mode = 0o0777
    # st_dev / st_rdev
    cont_device_id = None
    device_id = 0
    # inode number (st_ino)
    inode = None
    # Number of hardlink (st_nlink)
    nlink = 0
    # Owner / group
    uid = None
    gid = None
    # Size (st_size / st_blksize / st_blocks)
    size = 0
    blksize = 0
    blocks = 0
    # Times
    atime = 0
    atimensec = 0
    mtime = 0
    mtimensec = 0
    ctime = 0
    ctimensec = 0

    def __init__(self, number):
        self.number = number
        self.is_closed = False

    def stat(self):
        mode = self.file_type | self.file_mode
        return StatInfo(
            st_dev=self.cont_device_id, st_ino=self.inode,
            st_nlink=self.nlink, st_mode=mode,
            st_uid=self.uid, st_gid=self.gid,
            st_rdev=self.device_id, st_size=self.size,
            st_blksize=self.blksize, st_blocks=self.blocks,
            st_atime=self.atime, st_atimensec=self.atimensec,
            st_mtime=self.mtime, st_mtimensec=self.mtimensec,
            st_ctime=self.ctime, st_ctimensec=self.ctimensec
        )

    def close(self):
        self.is_closed = True


class FileDescriptorCharDevice(FileDescriptor):
    file_type = 0o0020000 # S_IFCHR
    file_mode = 0o0620
    cont_device_id = 1
    device_id = 1


class FileDescriptorSTDIN(FileDescriptorCharDevice):
    """Special file descriptor standinf for STDIN"""
    inode = 0

    def read(self, count):
        raise RuntimeError("Not implemented")


class FileDescriptorSTDOUT(FileDescriptorCharDevice):
    """Special file descriptor standinf for STDOUT"""
    inode = 1

    def write(self, data):
        print "[STDOUT] %s" % data.rstrip()


class FileDescriptorSTDERR(FileDescriptorCharDevice):
    """Special file descriptor standinf for STDERR"""
    inode = 2

    def write(self, data):
        print "[STDERR] %s" % data.rstrip()


class FileDescriptorDirectory(FileDescriptor):
    """FileDescription designing a directory"""

    file_type = 0o0040000 # S_IFDIR

    def __init__(self, number, filesystem, real_path):
        super(FileDescriptorDirectory, self).__init__(number)
        self.filesystem = filesystem
        self.real_path = real_path
        self.cur_listdir = None

    def listdir(self):
        if self.cur_listdir is None:
            self.cur_listdir = os.listdir(self.real_path)
        while self.cur_listdir:
            yield self.cur_listdir.pop()


class FileDescriptorRegularFile(FileDescriptor):
    """FileDescriptor designing a regular file"""

    file_type = 0o0100000 # S_IFREG

    def __init__(self, number, flags, filesystem, real_fd):
        super(FileDescriptorRegularFile, self).__init__(number)
        self.flags = flags
        self.filesystem = filesystem
        self.real_fd = real_fd

    def write(self, data):
        raise RuntimeError("Not implemented")

    def read(self, count):
        return os.read(self.real_fd, count)

    def close(self):
        super(FileDescriptorRegularFile, self).close()
        return os.close(self.real_fd)

    def lseek(self, offset, whence):
        return os.lseek(self.real_fd, offset, whence) # SEEK_SET

    def tell(self):
        return self.lseek(0, 1) # SEEK_CUR

    def seek(self, offset):
        return self.lseek(offset, 0) # SEEK_SET


class FileDescriptorSocket(FileDescriptor):
    """FileDescription standing for a socket"""

    file_type = 0o0140000 # S_IFSOCK

    def __init__(self, number, family, type_, protocol):
        super(FileDescriptorSocket, self).__init__(number)
        self.family = family
        self.type_ = type_
        self.protocol = protocol


class FileSystem(object):
    """File system abstraction
    Provides standard operations on the filesystem, (a bit like FUSE)

    API using FileSystem only used sandbox-side path. FileSystem should be the
    only object able to interact with real path, outside the sandbox.

    Thus, if `resolve_path` is correctly implemented and used, it should not be
    possible to modify files outside the sandboxed path
    """

    O_CLOEXEC = 0x80000
    device_id = 0x1234 # ID of device containing file (stat.st_dev)
    blocksize = 0x1000 # Size of block on this filesystem
    f_type = 0xef53 # (Type of filesystem) EXT4_SUPER_MAGIC
    nb_total_block = 0x1000
    nb_free_block = 0x100
    nb_avail_block = nb_free_block # Available to unprivileged user
    nb_total_fnode = 100 # Total file nodes in filesystem
    nb_free_fnode = 50
    max_filename_len = 256
    fragment_size = 0
    mount_flags = 0

    def __init__(self, base_path, linux_env):
        self.base_path = base_path
        self.linux_env = linux_env
        self.passthrough = []
        self.path_to_inode = {} # Real path (post-resolution) -> inode number

    def resolve_path(self, path, follow_link=True):
        """Resolve @path to the corresponding sandboxed path"""
        # Remove '../', etc.
        path = os.path.normpath(path)

        # Passthrough
        for passthrough in self.passthrough:
            if hasattr(passthrough, "match"):
                if passthrough.match(path):
                    return path
            elif passthrough == path:
                return path

        # Remove leading '/' if any (multiple '//' are handled by 'abspath'
        if path.startswith(os.path.sep):
            path = path[1:]

        base_path = os.path.abspath(self.base_path)
        out_path = os.path.join(base_path, path)
        assert out_path.startswith(base_path + os.path.sep)
        if os.path.islink(out_path):
            link_target = os.readlink(out_path)
            # Link can be absolute or relative -> absolute
            link = os.path.normpath(os.path.join(os.path.dirname(path), link_target))
            if follow_link:
                out_path = self.resolve_path(link)
            else:
                return link
        return out_path

    def get_path_inode(self, real_path):
        inode = self.path_to_inode.setdefault(real_path, len(self.path_to_inode))
        return inode

    def exists(self, path):
        sb_path = self.resolve_path(path)
        return os.path.exists(sb_path)

    def readlink(self, path):
        sb_path = self.resolve_path(path, follow_link=False)
        if not os.path.islink(sb_path):
            return None
        return os.path.readlink(sb_path)

    def statfs(self):
        return StatFSInfo(
            f_type=self.f_type, f_bsize=self.blocksize,
            f_blocks=self.nb_total_block, f_bfree=self.nb_free_block,
            f_bavail=self.nb_avail_block, f_files=self.nb_total_fnode,
            f_ffree=self.nb_free_fnode, f_fsid=self.device_id,
            f_namelen=self.max_filename_len,
            f_frsize=self.fragment_size, f_flags=self.mount_flags, f_spare=0)

    def getattr_(self, path, follow_link=True):
        sb_path = self.resolve_path(path, follow_link=follow_link)
        flags = os.O_RDONLY
        if os.path.isdir(sb_path):
            flags |= os.O_DIRECTORY

        fd = self.open_(path, flags, follow_link=follow_link)
        info = self.linux_env.fstat(fd)
        self.linux_env.close(fd)
        return info

    def open_(self, path, flags, follow_link=True):
        path = self.resolve_path(path, follow_link=follow_link)
        if not os.path.exists(path):
            # ENOENT (No such file or directory)
            return -1
        fd = self.linux_env.next_fd()

        # Ignore some flags
        for flag_to_ignore in [
                self.O_CLOEXEC,
                os.O_NONBLOCK
        ]:
            if flags & flag_to_ignore == flag_to_ignore:
                flags ^= flag_to_ignore

        if os.path.isdir(path):
            assert flags & os.O_DIRECTORY == os.O_DIRECTORY
            flags ^= os.O_DIRECTORY
            if flags == os.O_RDONLY:
                fdesc = FileDescriptorDirectory(fd, self, path)
            else:
                raise RuntimeError("Not implemented")
        elif os.path.isfile(path):
            if flags == os.O_RDONLY:
                # Read only
                real_fd = os.open(path, os.O_RDONLY)
            else:
                raise RuntimeError("Not implemented")
            fdesc = FileDescriptorRegularFile(fd, flags, self, real_fd)

        elif os.path.islink(path):
            raise RuntimeError("Not implemented")
        else:
            raise RuntimeError("Unknown file type for %r" % path)

        self.linux_env.file_descriptors[fd] = fdesc
        # Set stat info
        fdesc.cont_device_id = self.device_id
        fdesc.inode = self.get_path_inode(path)
        fdesc.uid = self.linux_env.user_uid
        fdesc.gid = self.linux_env.user_gid
        size = os.path.getsize(path)
        fdesc.size = size
        fdesc.blksize = self.blocksize
        fdesc.blocks = (size + ((512 - (size % 512)) % 512)) / 512
        return fd


class Networking(object):
    """Network abstraction"""

    def __init__(self, linux_env):
        self.linux_env = linux_env

    def socket(self, family, type_, protocol):
        fd = self.linux_env.next_fd()
        fdesc = FileDescriptorSocket(fd, family, type_, protocol)
        self.linux_env.file_descriptors[fd] = fdesc
        return fd


class LinuxEnvironment(object):
    """A LinuxEnvironment regroups information to simulate a Linux-like
    environment"""

    # To be overrided
    platform_arch = None

    # User information
    user_uid = 1000
    user_euid = 1000
    user_gid = 1000
    user_egid = 1000
    user_name = "user"

    # Memory mapping information
    brk_current = 0x74000000
    mmap_current = 0x75000000

    # System information
    sys_sysname = "Linux"
    sys_nodename = "user-pc"
    sys_release = "4.13.0-19-generic"
    sys_version = "#22-Ubuntu"
    sys_machine = None

    # Filesystem
    filesystem_base = "file_sb"
    file_descriptors = None

    # Current process
    process_tid = 1000
    process_pid = 1000

    # Syscall restrictions
    ioctl_allowed = None # list of (fd, cmd), None value for wildcard
    ioctl_disallowed = None # list of (fd, cmd), None value for wildcard

    # Time
    base_time = 1531900000

    def __init__(self):
        stdin = FileDescriptorSTDIN(0)
        stdout = FileDescriptorSTDOUT(1)
        stderr = FileDescriptorSTDERR(2)
        for std in [stdin, stdout, stderr]:
            std.uid = self.user_uid
            std.gid = self.user_gid
        self.file_descriptors = {
            0: stdin,
            1: stdout,
            2: stderr,
        }
        self.ioctl_allowed = [
            (0, termios.TCGETS),
            (0, termios.TIOCGWINSZ),
            (0, termios.TIOCSWINSZ),
            (1, termios.TCGETS),
            (1, termios.TIOCGWINSZ),
            (1, termios.TIOCSWINSZ),
        ]
        self.ioctl_disallowed = [
            (2, termios.TCGETS),
            (0, termios.TCSETSW),
        ]
        self.filesystem = FileSystem(self.filesystem_base, self)
        self.network = Networking(self)

    def next_fd(self):
        return len(self.file_descriptors)

    def clock_gettime(self):
        out = self.base_time
        self.base_time += 1
        return out

    def open_(self, path, flags, follow_link=True):
        """Stub for 'open' syscall"""
        return self.filesystem.open_(path, flags, follow_link=follow_link)

    def socket(self, family, type_, protocol):
        """Stub for 'socket' syscall"""
        return self.network.socket(family, type_, protocol)

    def fstat(self, fd):
        """Get file status through fd"""
        fdesc = self.file_descriptors.get(fd)
        if fdesc is None:
            return None
        return fdesc.stat()

    def stat(self, path):
        """Get file status through path"""
        return self.filesystem.getattr_(path)

    def lstat(self, path):
        """Get file status through path (not following links)"""
        return self.filesystem.getattr_(path, follow_link=False)

    def close(self, fd):
        """Stub for 'close' syscall"""
        fdesc = self.file_descriptors.get(fd)
        if fdesc is None:
            return None
        return fdesc.close()


class LinuxEnvironment_x86_64(LinuxEnvironment):
    platform_arch = "x86_64"
    sys_machine = "x86_64"


class AuxVec(object):
    """Auxiliary vector abstraction, filled with default values
    (mainly based on https://lwn.net/Articles/519085)

    # Standard usage
    >>> auxv = AuxVec(elf_base_addr, cont_target.entry_point, linux_env)

    # Enable AT_SECURE
    >>> auxv = AuxVec(..., AuxVec.AT_SECURE=1)
    # Modify AT_RANDOM
    >>> auxv = AuxVec(..., AuxVec.AT_RANDOM="\x00"*0x10)

    # Using AuxVec instance for stack preparation
    # First, fill memory with vectors data
    >>> for AT_number, data in auxv.data_to_map():
            dest_ptr = ...
            copy_to_dest(data, dest_ptr)
            auxv.ptrs[AT_number] = dest_ptr
    # Then, get the key: value (with value being sometime a pointer)
    >>> for auxid, auxval in auxv.iteritems():
            ...
    """

    AT_PHDR = 3
    AT_PHNUM = 5
    AT_PAGESZ = 6
    AT_ENTRY = 9
    AT_UID = 11
    AT_EUID = 12
    AT_GID = 13
    AT_EGID = 14
    AT_PLATFORM = 15
    AT_HWCAP = 16
    AT_SECURE = 23
    AT_RANDOM = 25
    AT_SYSINFO_EHDR = 33

    def __init__(self, elf_phdr_vaddr, entry_point, linux_env, **kwargs):
        """Instanciate an AuxVec, with required elements:
        - elf_phdr_vaddr: virtual address of the ELF's PHDR in memory
        - entry_point: virtual address of the ELF entry point
        - linux_env: LinuxEnvironment instance, used to provides some of the
          option values

        Others options can be overrided by named arguments

        """
        self.info = {
            self.AT_PHDR: elf_phdr_vaddr,
            self.AT_PHNUM: 9,
            self.AT_PAGESZ: 0x1000,
            self.AT_ENTRY: entry_point,
            self.AT_UID: linux_env.user_uid,
            self.AT_EUID: linux_env.user_euid,
            self.AT_GID: linux_env.user_gid,
            self.AT_EGID: linux_env.user_egid,
            self.AT_PLATFORM: linux_env.platform_arch,
            self.AT_HWCAP: 0,
            self.AT_SECURE: 0,
            self.AT_RANDOM: "\x00" * 0x10,
            # vDSO is not mandatory
            self.AT_SYSINFO_EHDR: None,
        }
        self.info.update(kwargs)
        self.ptrs = {} # info key -> corresponding virtual address

    def data_to_map(self):
        """Iterator on (AT_number, data)
        Once the data has been mapped, the corresponding ptr must be set in
        'self.ptrs[AT_number]'
        """
        for AT_number in [self.AT_PLATFORM, self.AT_RANDOM]:
            yield (AT_number, self.info[AT_number])

    def iteritems(self):
        """Iterator on auxiliary vector id and values"""
        for AT_number, value in self.info.iteritems():
            if AT_number in self.ptrs:
                value = self.ptrs[AT_number]
            if value is None:
                # AT to ignore
                continue
            yield (AT_number, value)


def prepare_loader_stack_x86_64(jitter, argv, envp, auxv,
                                hlt_address=0x13371acc):
    """Fill the stack with enough information to run a linux loader

    @jitter: Jitter instance
    @argv: list of strings
    @envp: dict of environment variables names to their values
    @auxv: AuxVec instance
    @hlt_address (default to 0x13371acc): stopping address

    Example of use:
    >>> jitter = machine.jitter()
    >>> jitter.init_stack()
    >>> linux_env = LinuxEnvironment_x86_64()
    >>> argv = ["/bin/ls", "-lah"]
    >>> envp = {"PATH": "/usr/local/bin", "USER": linux_env.user_name}
    >>> auxv = AuxVec(elf_base_addr, entry_point, linux_env)
    >>> prepare_loader_stack_x86_64(jitter, argv, envp, auxv)
    # One may want to enable syscall handling here
    # The program can now run from the loader
    >>> jitter.init_run(ld_entry_point)
    >>> jitter.continue_run()
    """
    # Stack layout looks like
    # [data]
    #  - auxv values
    #  - envp name=value
    #  - argv arguments
    # [auxiliary vector]
    # [environment pointer]
    # [argument vector]

    for AT_number, data in auxv.data_to_map():
        data += "\x00"
        jitter.cpu.RSP -= len(data)
        ptr = jitter.cpu.RSP
        jitter.vm.set_mem(ptr, data)
        auxv.ptrs[AT_number] = ptr

    env_ptrs = []
    for name, value in envp.iteritems():
        env = "%s=%s\x00" % (name, value)
        jitter.cpu.RSP -= len(env)
        ptr = jitter.cpu.RSP
        jitter.vm.set_mem(ptr, env)
        env_ptrs.append(ptr)

    argv_ptrs = []
    for arg in argv:
        arg += "\x00"
        jitter.cpu.RSP -= len(arg)
        ptr = jitter.cpu.RSP
        jitter.vm.set_mem(ptr, arg)
        argv_ptrs.append(ptr)

    jitter.push_uint64_t(hlt_address)
    jitter.push_uint64_t(0)
    jitter.push_uint64_t(0)
    for auxid, auxval in auxv.iteritems():
        jitter.push_uint64_t(auxval)
        jitter.push_uint64_t(auxid)
    jitter.push_uint64_t(0)
    for ptr in reversed(env_ptrs):
        jitter.push_uint64_t(ptr)
    jitter.push_uint64_t(0)
    for ptr in reversed(argv_ptrs):
        jitter.push_uint64_t(ptr)
    jitter.push_uint64_t(len(argv))

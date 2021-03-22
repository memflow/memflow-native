use memflow::prelude::v1::*;

use libc::{iovec, pid_t, sysconf, _SC_IOV_MAX};
use std::ffi::c_void;

use procfs::process::MMapPath;
use procfs::KernelModule;

use itertools::Itertools;

#[derive(Clone, Copy)]
#[repr(transparent)]
struct IoSendVec(iovec);

unsafe impl Send for IoSendVec {}

pub struct LinuxOS {
    info: OSInfo,
    cached_modules: Vec<KernelModule>
}

impl Clone for LinuxOS {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            cached_modules: vec![]
        }
    }
}

impl Default for LinuxOS {
    fn default() -> Self {
        let info = OSInfo {
            base: Address::NULL,
            size: 0,
            arch: ArchitectureIdent::X86(64, false),
        };

        Self { info, cached_modules: vec![] }
    }
}

impl<'a> OSInner<'a> for LinuxOS {
    type ProcessType = LinuxProcess;
    type IntoProcessType = LinuxProcess;

    /// Walks a process list and calls a callback for each process structure address
    ///
    /// The callback is fully opaque. We need this style so that C FFI can work seamlessly.
    fn process_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        procfs::process::all_processes()
            .map_err(|_| Error(ErrorOrigin::OSLayer, ErrorKind::UnableToReadDir))?
            .into_iter()
            .map(|p| p.pid() as usize)
            .map(Address::from)
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});

        Ok(())
    }

    /// Find process information by its internal address
    fn process_info_by_address(&mut self, address: Address) -> Result<ProcessInfo> {
        let proc = procfs::process::Process::new(address.as_u64() as pid_t)
            .map_err(|_| Error(ErrorOrigin::OSLayer, ErrorKind::UnableToReadDir))?;

        Ok(ProcessInfo {
            address,
            pid: proc.pid() as PID,
            name: proc
                .cmdline()
                .ok()
                .map(|l| l.get(0).map(|s| s.split_whitespace().next().unwrap().to_string()))
                .flatten()
                .unwrap_or_else(|| {
                    proc.status()
                        .ok()
                        .map(|s| s.name)
                        .unwrap_or("unknown".to_string())
                })
                .into(),
            sys_arch: ArchitectureIdent::X86(64, false),
            proc_arch: ArchitectureIdent::X86(64, false),
        })
    }

    /// Construct a process by its info, borrowing the OS
    ///
    /// It will share the underlying memory resources
    fn process_by_info(&'a mut self, info: ProcessInfo) -> Result<Self::ProcessType> {
        LinuxProcess::try_new(info)
    }

    /// Construct a process by its info, consuming the OS
    ///
    /// This function will consume the Kernel instance and move its resources into the process
    fn into_process_by_info(mut self, info: ProcessInfo) -> Result<Self::IntoProcessType> {
        self.process_by_info(info)
    }

    /// Walks the OS module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        self.cached_modules = procfs::modules()
            .map_err(|_| Error(ErrorOrigin::OSLayer, ErrorKind::UnableToReadDir))?
            .into_iter()
            .map(|(_, v)| v)
            .collect();

        (0..self.cached_modules.len())
            .map(Address::from)
            .take_while(|a| callback.call(*a))
            .for_each(|_| {});

        Ok(())
    }

    /// Retrieves a module by its structure address
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    fn module_by_address(&mut self, address: Address) -> Result<ModuleInfo> {
        self.cached_modules
            .iter()
            .skip(address.as_usize())
            .next()
            .map(|km| ModuleInfo {
                address,
                size: km.size as usize,
                base: Address::NULL,
                name: km.name.clone().into(),
                arch: self.info.arch,
                path: "".into(),
                parent_process: Address::INVALID,
            })
            .ok_or(Error(ErrorOrigin::OSLayer, ErrorKind::NotFound))
    }

    /// Retrieves the OS info
    fn info(&self) -> &OSInfo {
        &self.info
    }
}

#[derive(Clone)]
pub struct LinuxProcess {
    virt_mem: ProcessVirtualMemory,
    proc: procfs::process::Process,
    info: ProcessInfo,
    cached_maps: Vec<procfs::process::MemoryMap>,
    cached_module_maps: Vec<procfs::process::MemoryMap>,
}

impl LinuxProcess {
    pub fn try_new(info: ProcessInfo) -> Result<Self> {
        Ok(Self {
            virt_mem: ProcessVirtualMemory::new(&info),
            proc: procfs::process::Process::new(info.pid as pid_t)
                .map_err(|_| Error(ErrorOrigin::OSLayer, ErrorKind::UnableToReadDir))?,
            info,
            cached_maps: vec![],
            cached_module_maps: vec![],
        })
    }

    pub fn mmap_path_to_name_string(path: &MMapPath) -> ReprCStr {
        match path {
            MMapPath::Path(buf) => buf
                .file_name()
                .map(|o| o.to_str())
                .flatten()
                .unwrap_or("unknown")
                .into(),
            MMapPath::Heap => "[heap]".into(),
            MMapPath::Stack => "[stack]".into(),
            MMapPath::TStack(_) => "[tstack]".into(),
            MMapPath::Vdso => "[vdso]".into(),
            MMapPath::Vvar => "[vvar]".into(),
            MMapPath::Vsyscall => "[vsyscall]".into(),
            MMapPath::Anonymous => "[anonymous]".into(),
            MMapPath::Other(s) => s.as_str().into(),
        }
    }

    pub fn mmap_path_to_path_string(path: &MMapPath) -> ReprCStr {
        match path {
            MMapPath::Path(buf) => buf
                .to_str()
                .unwrap_or("unknown")
                .into(),
            MMapPath::Heap => "[heap]".into(),
            MMapPath::Stack => "[stack]".into(),
            MMapPath::TStack(_) => "[tstack]".into(),
            MMapPath::Vdso => "[vdso]".into(),
            MMapPath::Vvar => "[vvar]".into(),
            MMapPath::Vsyscall => "[vsyscall]".into(),
            MMapPath::Anonymous => "[anonymous]".into(),
            MMapPath::Other(s) => s.as_str().into(),
        }
    }
}

impl Process for LinuxProcess {
    type VirtualMemoryType = ProcessVirtualMemory;

    fn virt_mem(&mut self) -> &mut Self::VirtualMemoryType {
        &mut self.virt_mem
    }

    /// Walks the process' module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `target_arch` - sets which architecture to retrieve the modules for (if emulated). Choose
    /// between `Some(ProcessInfo::sys_arch())`, and `Some(ProcessInfo::proc_arch())`. `None` for all.
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: ModuleAddressCallback,
    ) -> Result<()> {
        self.cached_maps = self
            .proc
            .maps()
            .map_err(|_| Error(ErrorOrigin::OSLayer, ErrorKind::UnableToReadDir))?;

        self.cached_module_maps = self
            .cached_maps
            .iter()
            .filter(|map| {
                if let MMapPath::Path(_) = map.pathname {
                    true
                } else {
                    false
                }
            })
            .cloned()
            .coalesce(|m1, m2| {
                if m1.address.1 == m2.address.0
                    && m2.offset - m1.offset == m1.address.1 - m1.address.0
                    && m1.dev == m2.dev
                    && m1.inode == m2.inode
                {
                    Ok(procfs::process::MemoryMap {
                        address: (m1.address.0, m2.address.1),
                        perms: String::new(),
                        offset: m1.offset,
                        dev: m1.dev,
                        inode: m1.inode,
                        pathname: m1.pathname,
                    })
                } else {
                    Err((m1, m2))
                }
            })
            .collect();

        self.cached_module_maps
            .iter()
            .enumerate()
            .filter(|_| target_arch == None || Some(&self.info().sys_arch) == target_arch)
            .take_while(|(i, _)| {
                callback.call(ModuleAddressInfo {
                    address: Address::from(*i as u64),
                    arch: self.info.proc_arch,
                })
            })
            .for_each(|_| {});

        Ok(())
    }

    /// Retrieves a module by its structure address and architecture
    ///
    /// # Arguments
    /// * `address` - address where module's information resides in
    /// * `architecture` - architecture of the module. Should be either `ProcessInfo::proc_arch`, or `ProcessInfo::sys_arch`.
    fn module_by_address(
        &mut self,
        address: Address,
        architecture: ArchitectureIdent,
    ) -> Result<ModuleInfo> {
        if architecture != self.info.sys_arch {
            return Err(Error(ErrorOrigin::OSLayer, ErrorKind::NotFound));
        }

        self.cached_module_maps
            .iter()
            .skip(address.as_usize())
            .next()
            .map(|map| ModuleInfo {
                address,
                parent_process: self.info.address,
                base: Address::from(map.address.0 as u64),
                size: map.address.1 as usize,
                name: Self::mmap_path_to_name_string(&map.pathname),
                path: Self::mmap_path_to_path_string(&map.pathname),
                arch: self.info.sys_arch,
            })
            .ok_or(Error(ErrorOrigin::OSLayer, ErrorKind::NotFound))
    }

    /// Retrieves address of the primary module structure of the process
    ///
    /// This will generally be for the initial executable that was run
    fn primary_module_address(&mut self) -> Result<Address> {
        // TODO: Is it always 0th mod?
        Ok(Address::from(0))
    }

    /// Retrieves the process info
    fn info(&self) -> &ProcessInfo {
        &self.info
    }
}

#[derive(Clone)]
pub struct ProcessVirtualMemory {
    pid: pid_t,
    temp_iov: Box<[IoSendVec]>,
}

impl ProcessVirtualMemory {
    fn new(info: &ProcessInfo) -> Self {
        let iov_max = unsafe { sysconf(_SC_IOV_MAX) } as usize;

        Self {
            pid: info.pid as pid_t,
            temp_iov: vec![
                IoSendVec {
                    0: iovec {
                        iov_base: std::ptr::null_mut::<c_void>(),
                        iov_len: 0
                    }
                };
                iov_max * 2
            ]
            .into_boxed_slice(),
        }
    }

    fn vm_error() -> ErrorKind {
        match unsafe { *libc::__errno_location() } {
            libc::EFAULT => ErrorKind::OutOfBounds,
            libc::EINVAL => ErrorKind::ArgValidation,
            libc::ENOMEM => ErrorKind::OutOfBounds,
            libc::EPERM => ErrorKind::NotSupported, // ErrorKind::Permissions
            libc::ESRCH => ErrorKind::ProcessNotFound,
            _ => ErrorKind::Unknown,
        }
    }
}

impl VirtualMemory for ProcessVirtualMemory {
    fn virt_read_raw_list(&mut self, data: &mut [VirtualReadData]) -> PartialResult<()> {
        let max_iov = self.temp_iov.len() / 2;
        let (iov_local, iov_remote) = self.temp_iov.split_at_mut(max_iov);

        let mut ret = Ok(());

        for chunk in data.chunks_mut(max_iov) {
            let mut cnt = 0;

            for (d, (liov, riov)) in chunk
                .iter_mut()
                .zip(iov_local.iter_mut().zip(iov_remote.iter_mut()))
            {
                cnt += d.1.len() as isize;

                liov.0 = iovec {
                    iov_base: d.1.as_mut_ptr() as *mut c_void,
                    iov_len: d.1.len(),
                };

                riov.0 = iovec {
                    iov_base: d.0.as_usize() as *mut c_void,
                    iov_len: d.1.len(),
                };
            }

            match unsafe {
                libc::process_vm_readv(
                    self.pid,
                    iov_local.as_ptr().cast(),
                    chunk.len() as u64,
                    iov_remote.as_ptr().cast(),
                    chunk.len() as u64,
                    0,
                )
            } {
                -1 => Err(Error(ErrorOrigin::OSLayer, Self::vm_error()))?,
                sz if sz < cnt => {
                    ret = Err(PartialError::PartialVirtualRead(()));
                }
                _ => {}
            }
        }

        ret
    }

    fn virt_write_raw_list(&mut self, data: &[VirtualWriteData]) -> PartialResult<()> {
        let max_iov = self.temp_iov.len() / 2;
        let (iov_local, iov_remote) = self.temp_iov.split_at_mut(max_iov);

        let mut ret = Ok(());

        for chunk in data.chunks(max_iov) {
            let mut cnt = 0;

            for (d, (liov, riov)) in chunk
                .iter()
                .zip(iov_local.iter_mut().zip(iov_remote.iter_mut()))
            {
                cnt += d.1.len() as isize;

                liov.0 = iovec {
                    iov_base: d.1.as_ptr() as *mut c_void,
                    iov_len: d.1.len(),
                };

                riov.0 = iovec {
                    iov_base: d.0.as_usize() as *mut c_void,
                    iov_len: d.1.len(),
                };
            }

            match unsafe {
                libc::process_vm_writev(
                    self.pid,
                    iov_local.as_ptr().cast(),
                    chunk.len() as u64,
                    iov_remote.as_ptr().cast(),
                    chunk.len() as u64,
                    0,
                )
            } {
                -1 => Err(Error(ErrorOrigin::OSLayer, Self::vm_error()))?,
                sz if sz < cnt => {
                    ret = Err(PartialError::PartialVirtualRead(()));
                }
                _ => {}
            }
        }

        ret
    }

    fn virt_page_info(&mut self, _addr: Address) -> Result<Page> {
        Err(Error(ErrorOrigin::OSLayer, ErrorKind::NotSupported))
    }

    fn virt_translation_map_range(
        &mut self,
        _start: Address,
        _end: Address,
    ) -> Vec<(Address, usize, PhysicalAddress)> {
        vec![]
    }

    fn virt_page_map_range(
        &mut self,
        gap_size: usize,
        start: Address,
        end: Address,
    ) -> Vec<(Address, usize)> {
        let mut out = vec![];

        procfs::process::Process::new(self.pid)
            .ok()
            .map(|i| i.maps().ok())
            .flatten()
            .map(|maps| maps.into_iter())
            .map(|maps| {
                out.extend(maps.into_iter().filter(|map| {
                    Address::from(map.address.1) > start && Address::from(map.address.0) < end
                })
                .map(|map| (Address::from(map.address.0), (map.address.1 - map.address.0) as usize))
                    .map(|(s, sz)| if s < start {
                        let diff = start - s;
                        (start, sz - diff)
                    } else {
                        (s, sz)
                    })
                    .map(|(s, sz)| if s + sz > end {
                        let diff = s - end;
                        (s, sz - diff)
                    } else {
                        (s, sz)
                    })
                .coalesce(|a, b| if a.0 + a.1 + gap_size >= b.0 {
                    Ok((a.0, b.0 - a.0 + b.1))
                } else {
                    Err((a, b))
                }))
            });

        out
    }
}

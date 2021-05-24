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

pub struct LinuxOs {
    info: OsInfo,
    cached_modules: Vec<KernelModule>,
}

impl Clone for LinuxOs {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            cached_modules: vec![],
        }
    }
}

impl Default for LinuxOs {
    fn default() -> Self {
        let info = OsInfo {
            base: Address::NULL,
            size: 0,
            arch: ArchitectureIdent::X86(64, false),
        };

        Self {
            info,
            cached_modules: vec![],
        }
    }
}

/// Epic hack. TODO: Remove
pub struct Nop {}

impl PhysicalMemory for Nop {
    fn phys_read_raw_list(&mut self, _data: &mut [PhysicalReadData]) -> Result<()> {
        Err(ErrorKind::NotSupported.into())
    }

    fn phys_write_raw_list(&mut self, _data: &[PhysicalWriteData]) -> Result<()> {
        Err(ErrorKind::NotSupported.into())
    }

    fn set_mem_map(&mut self, _mem_map: MemoryMap<(Address, usize)>) {}

    fn metadata(&self) -> PhysicalMemoryMetadata {
        PhysicalMemoryMetadata {
            size: 0,
            readonly: true,
        }
    }
}

impl VirtualMemory for Nop {
    fn virt_read_raw_list(&mut self, _data: &mut [VirtualReadData]) -> PartialResult<()> {
        Err(PartialError::Error(ErrorKind::NotSupported.into()))
    }

    fn virt_write_raw_list(&mut self, _data: &[VirtualWriteData]) -> PartialResult<()> {
        Err(PartialError::Error(ErrorKind::NotSupported.into()))
    }

    fn virt_page_info(&mut self, _addr: Address) -> Result<Page> {
        Err(ErrorKind::NotSupported.into())
    }

    fn virt_page_map_range(
        &mut self,
        _gap_size: usize,
        _start: Address,
        _end: Address,
    ) -> Vec<(Address, usize)> {
        vec![]
    }

    fn virt_translation_map_range(
        &mut self,
        _start: Address,
        _end: Address,
    ) -> Vec<(Address, usize, PhysicalAddress)> {
        vec![]
    }
}

impl<'a> OsInner<'a> for LinuxOs {
    type ProcessType = LinuxProcess;
    type IntoProcessType = LinuxProcess;

    type VirtualMemoryType = Nop;
    type PhysicalMemoryType = Nop;

    fn virt_mem(&mut self) -> Option<&mut Self::VirtualMemoryType> {
        None
    }

    fn phys_mem(&mut self) -> Option<&mut Self::PhysicalMemoryType> {
        None
    }

    /// Walks a process list and calls a callback for each process structure address
    ///
    /// The callback is fully opaque. We need this style so that C FFI can work seamlessly.
    fn process_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        procfs::process::all_processes()
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
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
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?;

        let command_line = proc
            .cmdline()
            .ok()
            .map(|v| v.join(" ").split('\0').collect_vec().join(" "))
            .unwrap_or_else(String::new)
            .into();

        let path = proc
            .cmdline()
            .ok()
            .map(|l| {
                l.get(0)
                    .map(|s| s.split('\0').next().unwrap_or("").to_string())
            })
            .flatten()
            .unwrap_or_else(|| {
                proc.status()
                    .ok()
                    .map(|s| s.name)
                    .unwrap_or("unknown".to_string())
            });

        let name = path.split(&['/', '\\'][..]).last().unwrap().into();

        let path = path.into();

        Ok(ProcessInfo {
            address,
            pid: proc.pid() as Pid,
            command_line,
            path,
            name,
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
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
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
                name: km
                    .name
                    .split("/")
                    .last()
                    .or(Some(""))
                    .map(ReprCString::from)
                    .unwrap(),
                arch: self.info.arch,
                path: km.name.clone().into(),
                parent_process: Address::INVALID,
            })
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    /// Retrieves the OS info
    fn info(&self) -> &OsInfo {
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
                .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?,
            info,
            cached_maps: vec![],
            cached_module_maps: vec![],
        })
    }

    pub fn mmap_path_to_name_string(path: &MMapPath) -> ReprCString {
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

    pub fn mmap_path_to_path_string(path: &MMapPath) -> ReprCString {
        match path {
            MMapPath::Path(buf) => buf.to_str().unwrap_or("unknown").into(),
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
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?;

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
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
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
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound))
    }

    fn module_import_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ImportCallback,
    ) -> Result<()> {
        let mut module_image = vec![0u8; info.size];
        self.virt_mem
            .virt_read_raw_into(info.base, &mut module_image)
            .data_part()?;

        use goblin::Object;

        fn import_call(
            iter: impl Iterator<Item = (usize, ReprCString)>,
            mut callback: ImportCallback,
        ) {
            iter.take_while(|(offset, name)| {
                callback.call(ImportInfo {
                    name: name.clone(),
                    offset: *offset,
                })
            })
            .for_each(|_| {});
        }

        match Object::parse(&module_image).map_err(|_| ErrorKind::InvalidExeFile)? {
            Object::Elf(elf) => {
                let iter = elf
                    .dynsyms
                    .iter()
                    .filter(|s| s.is_import())
                    .filter_map(|s| {
                        elf.dynstrtab
                            .get(s.st_name)
                            .map(|r| r.ok())
                            .flatten()
                            .map(|n| (s.st_value as usize, ReprCString::from(n)))
                    });

                import_call(iter, callback);

                Ok(())
            }
            Object::PE(pe) => {
                let iter = pe
                    .imports
                    .iter()
                    .map(|e| (e.offset, e.name.as_ref().into()));

                import_call(iter, callback);

                Ok(())
            }
            _ => Err(ErrorKind::InvalidExeFile.into()),
        }
    }

    fn module_export_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ExportCallback,
    ) -> Result<()> {
        let mut module_image = vec![0u8; info.size];
        self.virt_mem
            .virt_read_raw_into(info.base, &mut module_image)
            .data_part()?;

        use goblin::Object;

        fn export_call(
            iter: impl Iterator<Item = (usize, ReprCString)>,
            mut callback: ExportCallback,
        ) {
            iter.take_while(|(offset, name)| {
                callback.call(ExportInfo {
                    name: name.clone(),
                    offset: *offset,
                })
            })
            .for_each(|_| {});
        }

        match Object::parse(&module_image).map_err(|_| ErrorKind::InvalidExeFile)? {
            Object::Elf(elf) => {
                let iter = elf
                    .dynsyms
                    .iter()
                    .filter(|s| !s.is_import())
                    .filter_map(|s| {
                        elf.dynstrtab
                            .get(s.st_name)
                            .map(|r| r.ok())
                            .flatten()
                            .map(|n| (s.st_value as usize, ReprCString::from(n)))
                    });

                export_call(iter, callback);

                Ok(())
            }
            Object::PE(pe) => {
                let iter = pe
                    .exports
                    .iter()
                    .filter_map(|e| e.name.map(|name| (e.offset, name.into())));

                export_call(iter, callback);

                Ok(())
            }
            _ => Err(ErrorKind::InvalidExeFile.into()),
        }
    }

    fn module_section_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: SectionCallback,
    ) -> Result<()> {
        let mut module_image = vec![0u8; info.size];
        self.virt_mem
            .virt_read_raw_into(info.base, &mut module_image)
            .data_part()?;

        use goblin::Object;

        fn section_call(
            iter: impl Iterator<Item = (usize, usize, ReprCString)>,
            mut callback: SectionCallback,
        ) {
            iter.take_while(|(base, size, name)| {
                callback.call(SectionInfo {
                    name: name.clone(),
                    base: Address::from(*base),
                    size: *size,
                })
            })
            .for_each(|_| {});
        }

        match Object::parse(&module_image).map_err(|_| ErrorKind::InvalidExeFile)? {
            Object::Elf(elf) => {
                let iter = elf.section_headers.iter().filter_map(|s| {
                    elf.shdr_strtab
                        .get(s.sh_name)
                        .map(|r| r.ok())
                        .flatten()
                        .map(|n| (s.sh_addr as usize, s.sh_size as usize, ReprCString::from(n)))
                });

                section_call(iter, callback);

                Ok(())
            }
            Object::PE(pe) => {
                let iter = pe.sections.iter().filter_map(|e| {
                    e.real_name.as_ref().map(|name| {
                        (
                            e.virtual_address as usize,
                            e.virtual_size as usize,
                            name.as_str().into(),
                        )
                    })
                });

                section_call(iter, callback);

                Ok(())
            }
            _ => Err(ErrorKind::InvalidExeFile.into()),
        }
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

    /// Retrieves the state of the process
    fn state(&mut self) -> ProcessState {
        ProcessState::Unknown
        /*if let Ok(exit_status) = self.virt_mem.virt_read::<Win32ExitStatus>(
            self.proc_info.base_info.address + self.offset_eproc_exit_status,
        ) {
            if exit_status == EXIT_STATUS_STILL_ACTIVE {
                ProcessState::Alive
            } else {
                ProcessState::Dead(exit_status)
            }
        } else {
            ProcessState::Unknown
        }*/
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

    fn vm_error() -> Option<ErrorKind> {
        let ret = match unsafe { *libc::__errno_location() } {
            libc::EFAULT => return None,
            libc::EINVAL => ErrorKind::ArgValidation,
            libc::ENOMEM => return None,
            libc::EPERM => ErrorKind::NotSupported, // ErrorKind::Permissions
            libc::ESRCH => ErrorKind::ProcessNotFound,
            _ => ErrorKind::Unknown,
        };

        Some(ret)
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

            let libcret = unsafe {
                libc::process_vm_readv(
                    self.pid,
                    iov_local.as_ptr().cast(),
                    chunk.len() as u64,
                    iov_remote.as_ptr().cast(),
                    chunk.len() as u64,
                    0,
                )
            };

            let vm_err = if libcret == -1 {
                Self::vm_error()
            } else {
                None
            };

            match vm_err {
                Some(err) => Err(Error(ErrorOrigin::OsLayer, err))?,
                _ => {
                    if libcret < cnt {
                        ret = Err(PartialError::PartialVirtualRead(()));
                    }
                }
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

            let libcret = unsafe {
                libc::process_vm_writev(
                    self.pid,
                    iov_local.as_ptr().cast(),
                    chunk.len() as u64,
                    iov_remote.as_ptr().cast(),
                    chunk.len() as u64,
                    0,
                )
            };

            let vm_err = if libcret == -1 {
                Self::vm_error()
            } else {
                None
            };

            match vm_err {
                Some(err) => Err(Error(ErrorOrigin::OsLayer, err))?,
                _ => {
                    if libcret < cnt {
                        ret = Err(PartialError::PartialVirtualRead(()));
                    }
                }
            }
        }

        ret
    }

    fn virt_page_info(&mut self, _addr: Address) -> Result<Page> {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported))
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
                out.extend(
                    maps.into_iter()
                        .filter(|map| {
                            Address::from(map.address.1) > start
                                && Address::from(map.address.0) < end
                        })
                        .filter(|m| !m.perms.starts_with("---"))
                        .map(|map| {
                            (
                                Address::from(map.address.0),
                                (map.address.1 - map.address.0) as usize,
                            )
                        })
                        .map(|(s, sz)| {
                            if s < start {
                                let diff = start - s;
                                (start, sz - diff)
                            } else {
                                (s, sz)
                            }
                        })
                        .map(|(s, sz)| {
                            if s + sz > end {
                                let diff = s - end;
                                (s, sz - diff)
                            } else {
                                (s, sz)
                            }
                        })
                        .coalesce(|a, b| {
                            if a.0 + a.1 + gap_size >= b.0 {
                                Ok((a.0, b.0 - a.0 + b.1))
                            } else {
                                Err((a, b))
                            }
                        }),
                )
            });

        out
    }
}

use memflow::cglue;
use memflow::os::process::*;
use memflow::prelude::v1::*;

use super::ProcessVirtualMemory;

use libc::pid_t;

use procfs::process::{MMPermissions, MMapExtension, MMapPath};

use itertools::Itertools;

pub struct LinuxProcess {
    virt_mem: ProcessVirtualMemory,
    pid: pid_t,
    info: ProcessInfo,
}

impl Clone for LinuxProcess {
    fn clone(&self) -> Self {
        Self {
            virt_mem: self.virt_mem.clone(),
            pid: self.pid,
            info: self.info.clone(),
        }
    }
}

impl LinuxProcess {
    fn proc_handle(&self) -> Result<procfs::process::Process> {
        procfs::process::Process::new(self.pid)
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))
    }

    fn module_maps(&self) -> Result<Vec<procfs::process::MemoryMap>> {
        let maps = self
            .proc_handle()?
            .maps()
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))?
            .memory_maps;

        Ok(maps
            .into_iter()
            .filter(|map| matches!(map.pathname, MMapPath::Path(_)))
            .coalesce(|m1, m2| {
                if m1.address.1 == m2.address.0
                    // When the file gets mapped in memory, offsets change.
                    // && m2.offset - m1.offset == m1.address.1 - m1.address.0
                    && m1.dev == m2.dev
                    && m1.inode == m2.inode
                {
                    Ok(procfs::process::MemoryMap {
                        address: (m1.address.0, m2.address.1),
                        perms: MMPermissions::NONE,
                        offset: m1.offset,
                        dev: m1.dev,
                        inode: m1.inode,
                        pathname: m1.pathname,
                        extension: MMapExtension::default(),
                    })
                } else {
                    Err((m1, m2))
                }
            })
            .collect())
    }

    pub fn try_new(info: ProcessInfo) -> Result<Self> {
        Ok(Self {
            virt_mem: ProcessVirtualMemory::new(&info),
            pid: info.pid as pid_t,
            info,
        })
    }

    pub fn mmap_path_to_name_string(path: &MMapPath) -> ReprCString {
        match path {
            MMapPath::Path(buf) => buf
                .file_name()
                .and_then(|o| o.to_str())
                .unwrap_or("unknown")
                .into(),
            MMapPath::Heap => "[heap]".into(),
            MMapPath::Stack => "[stack]".into(),
            MMapPath::TStack(_) => "[tstack]".into(),
            MMapPath::Vdso => "[vdso]".into(),
            MMapPath::Vvar => "[vvar]".into(),
            MMapPath::Vsyscall => "[vsyscall]".into(),
            MMapPath::Rollup => "[rollup]".into(),
            MMapPath::Anonymous => "[anonymous]".into(),
            MMapPath::Vsys(_) => "[vsys]".into(),
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
            MMapPath::Rollup => "[rollup]".into(),
            MMapPath::Anonymous => "[anonymous]".into(),
            MMapPath::Vsys(_) => "[vsys]".into(),
            MMapPath::Other(s) => s.as_str().into(),
        }
    }

    #[cfg(memflow_plugin_api = "2")]
    fn collect_envars(&self) -> Result<Vec<EnvVarInfo>> {
        let path = format!("/proc/{}/environ", self.pid);
        let data = std::fs::read(path)
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::EnvarNotFound))?;

        let mut out = Vec::new();
        for entry in data.split(|b| *b == 0).filter(|entry| !entry.is_empty()) {
            let entry = String::from_utf8_lossy(entry);
            if let Some((name, value)) = entry.split_once('=') {
                out.push(EnvVarInfo {
                    name: ReprCString::from(name),
                    value: ReprCString::from(value),
                    address: Address::NULL,
                    arch: self.info.proc_arch,
                });
            }
        }

        Ok(out)
    }
}

cglue_impl_group!(LinuxProcess, ProcessInstance, {});
cglue_impl_group!(LinuxProcess, IntoProcessInstance, {});

impl Process for LinuxProcess {
    /// Walks the process' module list and calls the provided callback for each module structure
    /// address
    ///
    /// # Arguments
    /// * `target_arch` - sets which architecture to retrieve the modules for (if emulated). Choose
    ///   between `Some(ProcessInfo::sys_arch())`, and `Some(ProcessInfo::proc_arch())`. `None` for all.
    /// * `callback` - where to pass each matching module to. This is an opaque callback.
    fn module_address_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: ModuleAddressCallback,
    ) -> Result<()> {
        let module_maps = self.module_maps()?;

        module_maps
            .iter()
            .enumerate()
            .filter(|_| target_arch.is_none() || Some(&self.info().sys_arch) == target_arch)
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

        let module_maps = self.module_maps()?;

        module_maps
            .get(address.to_umem() as usize)
            .map(|map| ModuleInfo {
                address,
                parent_process: self.info.address,
                base: Address::from(map.address.0),
                size: (map.address.1 - map.address.0) as umem,
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
        memflow::os::util::module_import_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_export_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ExportCallback,
    ) -> Result<()> {
        memflow::os::util::module_export_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_section_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: SectionCallback,
    ) -> Result<()> {
        memflow::os::util::module_section_list_callback(&mut self.virt_mem, info, callback)
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
    }

    /// Changes the dtb this process uses for memory translations.
    /// This function serves no purpose in memflow-native.
    fn set_dtb(&mut self, _dtb1: Address, _dtb2: Address) -> Result<()> {
        Ok(())
    }

    fn mapped_mem_range(
        &mut self,
        gap_size: imem,
        start: Address,
        end: Address,
        out: MemoryRangeCallback,
    ) {
        if let Ok(proc) = self.proc_handle() {
            if let Ok(maps) = proc
                .maps()
                .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))
            {
                maps.memory_maps
                    .into_iter()
                    .filter(|map| {
                        Address::from(map.address.1) > start && Address::from(map.address.0) < end
                    })
                    .filter(|m| m.perms.contains(MMPermissions::READ))
                    .map(|map| {
                        (
                            Address::from(map.address.0),
                            (map.address.1 - map.address.0) as umem,
                            PageType::empty()
                                .noexec(!map.perms.contains(MMPermissions::EXECUTE))
                                .write(map.perms.contains(MMPermissions::WRITE)),
                        )
                    })
                    .map(|(s, sz, perms)| {
                        if s < start {
                            let diff = start - s;
                            (start, sz - diff as umem, perms)
                        } else {
                            (s, sz, perms)
                        }
                    })
                    .map(|(s, sz, perms)| {
                        if s + sz > end {
                            let diff = (s + sz) - end;
                            (s, sz - diff as umem, perms)
                        } else {
                            (s, sz, perms)
                        }
                    })
                    .coalesce(|a, b| {
                        if gap_size >= 0 && a.0 + a.1 + gap_size as umem >= b.0 && a.2 == b.2 {
                            Ok((a.0, (b.0 - a.0) as umem + b.1, a.2))
                        } else {
                            Err((a, b))
                        }
                    })
                    .map(<_>::into)
                    .feed_into(out);
            }
        }
    }
    #[cfg(memflow_plugin_api = "2")]
    fn envar_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: EnvVarCallback,
    ) -> Result<()> {
        if let Some(arch) = target_arch {
            if *arch != self.info.proc_arch {
                return Ok(());
            }
        }

        for envar in self.collect_envars()? {
            if !callback.call(envar) {
                break;
            }
        }

        Ok(())
    }

    #[cfg(memflow_plugin_api = "2")]
    fn environment_block_address(&mut self, _architecture: ArchitectureIdent) -> Result<Address> {
        // Linux does not expose a stable public env-block pointer through procfs.
        Ok(Address::NULL)
    }

    #[cfg(memflow_plugin_api = "2")]
    fn envar_list_from_address(
        &mut self,
        _env_block: Address,
        architecture: ArchitectureIdent,
        callback: EnvVarCallback,
    ) -> Result<()> {
        self.envar_list_callback(Some(&architecture), callback)
    }
}

impl MemoryView for LinuxProcess {
    fn read_raw_iter(&mut self, data: ReadRawMemOps) -> Result<()> {
        self.virt_mem.read_raw_iter(data)
    }

    fn write_raw_iter(&mut self, data: WriteRawMemOps) -> Result<()> {
        self.virt_mem.write_raw_iter(data)
    }

    fn metadata(&self) -> MemoryViewMetadata {
        self.virt_mem.metadata()
    }
}

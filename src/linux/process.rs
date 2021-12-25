use memflow::cglue;
use memflow::os::process::*;
use memflow::prelude::v1::*;

use super::ProcessVirtualMemory;

use libc::pid_t;

use procfs::process::MMapPath;

use itertools::Itertools;

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

cglue_impl_group!(LinuxProcess, ProcessInstance, {});
cglue_impl_group!(LinuxProcess, IntoProcessInstance, {});

impl Process for LinuxProcess {
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
            .skip(address.to_umem() as usize)
            .next()
            .map(|map| ModuleInfo {
                address,
                parent_process: self.info.address,
                base: Address::from(map.address.0 as u64),
                size: map.address.1 as umem,
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

    fn mapped_mem_range(
        &mut self,
        gap_size: imem,
        start: Address,
        end: Address,
        out: MemoryRangeCallback,
    ) {
        if let Ok(maps) = self
            .proc
            .maps()
            .map_err(|_| Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir))
        {
            self.cached_maps = maps;

            self.cached_maps
                .iter()
                .filter(|map| {
                    Address::from(map.address.1) > start && Address::from(map.address.0) < end
                })
                .filter(|m| !m.perms.starts_with("---"))
                .map(|map| {
                    (
                        Address::from(map.address.0),
                        (map.address.1 - map.address.0) as umem,
                    )
                })
                .map(|(s, sz)| {
                    if s < start {
                        let diff = start - s;
                        (start, sz - diff as umem)
                    } else {
                        (s, sz)
                    }
                })
                .map(|(s, sz)| {
                    if s + sz > end {
                        let diff = s - end;
                        (s, sz - diff as umem)
                    } else {
                        (s, sz)
                    }
                })
                .coalesce(|a, b| {
                    if gap_size >= 0 && a.0 + a.1 + gap_size as umem >= b.0 {
                        Ok((a.0, (b.0 - a.0) as umem + b.1))
                    } else {
                        Err((a, b))
                    }
                })
                .map(<_>::into)
                .feed_into(out);
        }
    }
}

impl MemoryView for LinuxProcess {
    fn read_raw_iter<'a>(
        &mut self,
        data: CIterator<ReadData<'a>>,
        out_fail: &mut ReadFailCallback<'_, 'a>,
    ) -> Result<()> {
        self.virt_mem.read_raw_iter(data, out_fail)
    }

    fn write_raw_iter<'a>(
        &mut self,
        data: CIterator<WriteData<'a>>,
        out_fail: &mut WriteFailCallback<'_, 'a>,
    ) -> Result<()> {
        self.virt_mem.write_raw_iter(data, out_fail)
    }

    fn metadata(&self) -> MemoryViewMetadata {
        self.virt_mem.metadata()
    }
}

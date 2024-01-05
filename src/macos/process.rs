use memflow::cglue;
use memflow::os::process::*;
use memflow::prelude::v1::*;
use memflow::types::size;

use super::ProcessVirtualMemory;

use libc::{
    natural_t, proc_pidinfo, task_info, vnode_info_path, KERN_SUCCESS, LC_SEGMENT, LC_SEGMENT_64,
    VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use mach2::task_info::{task_dyld_info, TASK_DYLD_INFO};

const PROC_PIDREGIONINFO: i32 = 7;
const PROC_PIDREGIONPATHINFO: i32 = 8;

use core::mem::MaybeUninit;
use itertools::Itertools;

#[repr(C)]
#[allow(non_camel_case_types)]
struct proc_regionwithpathinfo {
    prp_prinfo: proc_regioninfo,
    prp_vip: vnode_info_path,
}

#[repr(C)]
#[derive(Default, Debug)]
#[allow(non_camel_case_types)]
struct proc_regioninfo {
    pri_protection: u32,
    pri_max_protection: u32,
    pri_inheritance: u32,
    pri_flags: u32,
    pri_offset: u64,
    pri_behavior: u32,
    pri_user_wired_count: u32,
    pri_user_tag: u32,
    pri_pages_resident: u32,
    pri_pages_shared_now_private: u32,
    pri_pages_swapped_out: u32,
    pri_pages_dirtied: u32,
    pri_ref_count: u32,
    pri_shadow_depth: u32,
    pri_share_mode: u32,
    pri_private_pages_resident: u32,
    pri_shared_pages_resident: u32,
    pri_obj_id: u32,
    pri_depth: u32,
    pri_address: u64,
    pri_size: u64,
}

#[repr(C)]
#[derive(Pod)]
#[allow(non_camel_case_types)]
struct dyld_all_image_infos {
    version: u32,
    info_array_count: u32,
    dyld_image_info: usize,
}

#[repr(C, packed(4))]
#[derive(Pod, Default, Clone, Copy)]
#[allow(non_camel_case_types)]
struct dyld_image_info {
    image_load_address: usize,
    image_file_path: usize,
    image_file_mod_date: usize,
}

#[repr(C)]
#[derive(Pod, Default, Clone, Copy)]
pub struct MachoHeader {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Pod, Default, Clone, Copy)]
pub struct MachoLoadCommand {
    pub ty: u32,
    pub sz: u32,
}

#[repr(C)]
#[derive(Pod, Default, Clone, Copy, Debug)]
pub struct MachoLcSegmentShared {
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

pub struct MacProcess {
    virt_mem: ProcessVirtualMemory,
    info: ProcessInfo,
    cached_maps: Vec<(Address, umem, PageType)>,
    cached_module_maps: Vec<(Address, umem, String)>,
}

impl Clone for MacProcess {
    fn clone(&self) -> Self {
        Self {
            virt_mem: self.virt_mem.clone(),
            info: self.info.clone(),
            cached_maps: self.cached_maps.clone(),
            cached_module_maps: self.cached_module_maps.clone(),
        }
    }
}

impl MacProcess {
    pub fn try_new(info: ProcessInfo) -> Result<Self> {
        Ok(Self {
            virt_mem: ProcessVirtualMemory::try_new(&info).map_err(|e| {
                log::error!("Unable to get port");
                e
            })?,
            info,
            cached_maps: vec![],
            cached_module_maps: vec![],
        })
    }

    pub fn update_cached_module_maps(&mut self) -> Result<()> {
        let mut info: task_dyld_info = unsafe { MaybeUninit::zeroed().assume_init() };

        self.cached_module_maps.clear();

        let mut count =
            (core::mem::size_of::<task_dyld_info>() / core::mem::size_of::<natural_t>()) as _;
        let ret = unsafe {
            task_info(
                self.virt_mem.port,
                TASK_DYLD_INFO,
                &mut info as *mut task_dyld_info as *mut _,
                &mut count,
            )
        };

        if ret != KERN_SUCCESS {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::Unknown));
        }

        // 0 -> 32-bit fmt
        // 1 -> 64-bit fmt
        // We need to verify that the format is the same as our native pointer width (usize size),
        // so that we don't misread nonsense.
        if 4 * (1 + info.all_image_info_format) as usize != core::mem::size_of::<usize>() {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported));
        }

        let infos = self.read::<dyld_all_image_infos>(info.all_image_info_addr.into())?;

        let mut left = infos.info_array_count as usize;
        let mut info_buf = vec![dyld_image_info::default(); core::cmp::min(128, left)];

        while left > 0 {
            let pos = infos.info_array_count as usize - left;

            let size = core::cmp::min(left, info_buf.len());

            self.read_into(
                Address::from(
                    infos.dyld_image_info + pos * core::mem::size_of::<dyld_image_info>(),
                ),
                &mut info_buf[..size],
            )?;
            left -= size;

            // And now, let's process the elements
            for i in &info_buf[..size] {
                // TODO: do the string reads concurrently
                let name = self.read_char_string(i.image_file_path.into())?;

                let start = Address::from(i.image_load_address);
                let mut end = start;

                // Now, we need to figure out the size of the image. To do this, iterate through
                // proc_regioninfo and grab all entries with identical (non-zero) inode number.
                let mut prwpi: proc_regionwithpathinfo =
                    unsafe { MaybeUninit::zeroed().assume_init() };
                let mut last_ino = 0;

                loop {
                    let size = core::mem::size_of::<proc_regionwithpathinfo>() as _;
                    let ret = unsafe {
                        proc_pidinfo(
                            self.info.pid as _,
                            PROC_PIDREGIONPATHINFO,
                            end.to_umem() as _,
                            &mut prwpi as *mut proc_regionwithpathinfo as *mut _,
                            size,
                        )
                    };

                    if ret <= 0 {
                        break;
                    }
                    if ret < size {
                        panic!("Invalid size returned from proc_pidinfo ({ret} vs {size})");
                    }

                    let ino = prwpi.prp_vip.vip_vi.vi_stat.vst_ino;

                    // FIXME: if we get ino 0 at the start, this usually indicates that we are
                    // dealing with a submap - submaps are how dyld's are shared across processes,
                    // meaning, practically shared libraries from dyld cache will be reported to be
                    // of size 0.
                    if ino == 0 || (last_ino != 0 && ino != last_ino) {
                        break;
                    }

                    let len = prwpi.prp_prinfo.pri_size as umem;
                    end = Address::from(prwpi.prp_prinfo.pri_address) + len;

                    last_ino = ino;
                }

                let mut mod_sz = (end - start) as umem;

                // FIXME: figure out a way without parsing the mach file...
                let _ = (|| {
                    let header = self.read::<MachoHeader>(start)?;

                    if header.sizeofcmds as usize > size::mb(16) {
                        return Err(ErrorKind::Unknown.into());
                    }

                    let cmdaddr = start
                        + core::mem::size_of::<MachoHeader>()
                        + if header.magic == 0xfeedfacf {
                            4
                        } else if header.magic == 0xfeedface {
                            0
                        } else {
                            return Err(ErrorKind::Unknown.into());
                        };

                    let mut cmds = vec![0; header.sizeofcmds as usize];

                    self.read_raw_into(cmdaddr, &mut cmds[..])?;

                    let view = DataView::from(&cmds[..]);

                    let mut cmdoff = 0;

                    let mut base_addr = None;
                    let mut all_seg_sz = 0;

                    for _ in 0..header.ncmds {
                        let hdr = view.read::<MachoLoadCommand>(cmdoff);

                        if let Some((addr, sz, seg)) = if hdr.ty == LC_SEGMENT {
                            let addr = view.read::<u32>(cmdoff + 24);
                            let sz = view.read::<u32>(cmdoff + 24 + 4);
                            Some((
                                addr as umem,
                                sz as umem,
                                view.read::<MachoLcSegmentShared>(cmdoff + 24 + 16),
                            ))
                        } else if hdr.ty == LC_SEGMENT_64 {
                            let addr = view.read::<u64>(cmdoff + 24);
                            let sz = view.read::<u64>(cmdoff + 24 + 8);
                            Some((
                                addr as umem,
                                sz as umem,
                                view.read::<MachoLcSegmentShared>(cmdoff + 24 + 32),
                            ))
                        } else {
                            None
                        } {
                            // Skip __PAGEZERO segment that has no sections
                            // TODO: should we also check for protection flags?
                            if seg.nsects != 0 {
                                if base_addr.is_none() {
                                    base_addr = Some(addr);
                                }
                                all_seg_sz =
                                    core::cmp::max(all_seg_sz, addr - base_addr.unwrap() + sz);
                            }
                        }

                        cmdoff += hdr.sz as usize;
                    }

                    mod_sz = core::cmp::max(all_seg_sz, mod_sz);

                    Result::Ok(())
                })();

                self.cached_module_maps.push((start, mod_sz, name));
            }
        }

        self.cached_module_maps.sort_by_key(|v| v.0);

        Ok(())
    }

    pub fn update_cached_maps(&mut self, mut start: Address, end: Address) {
        let mut pri: proc_regioninfo = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut last_pri: proc_regioninfo = unsafe { MaybeUninit::zeroed().assume_init() };

        self.cached_maps.clear();

        while start < end {
            // FIXME: use mach_vm_region_recurse to read into submaps.
            let size = core::mem::size_of::<proc_regioninfo>() as _;
            let ret = unsafe {
                proc_pidinfo(
                    self.info.pid as _,
                    PROC_PIDREGIONINFO,
                    start.to_umem() as _,
                    &mut pri as *mut proc_regioninfo as *mut _,
                    size,
                )
            };
            if ret <= 0 {
                break;
            }
            if ret < size {
                panic!("Invalid size returned from proc_pidinfo ({ret} vs {size})");
            }

            start = Address::from(pri.pri_address);
            let len = pri.pri_size as umem;
            let flags = pri.pri_protection as u32;

            // TODO: Verify VM_PROT_READ, but that requires changes in memflow
            let perms = if flags & VM_PROT_READ as u32 != 0 {
                PageType::NONE
                    .write((flags & VM_PROT_WRITE as u32) != 0)
                    .noexec((flags & VM_PROT_EXECUTE as u32) == 0)
            } else {
                PageType::NONE
            };

            pri.pri_pages_resident = 0;
            pri.pri_pages_swapped_out = 0;
            pri.pri_pages_dirtied = 0;
            pri.pri_private_pages_resident = 0;
            pri.pri_shared_pages_resident = 0;
            pri.pri_obj_id = 0;
            pri.pri_address = 0;
            pri.pri_size = 0;

            // If the map is contiguous and identital, then coalesce the entry, because memflow
            // currently does not expose any additional info about mappings, and the
            // split between multiple VM objects are merely a quirk of Darwin.
            //
            // Coalescing the regions brings more benefit, because then we can match better against
            // these mapping in other code.
            //
            // TODO: do we want to verify increasing pri_obj_id or not
            if !self.cached_maps.is_empty()
                && unsafe {
                    let pri = &*(&pri as *const _
                        as *const [u8; core::mem::size_of::<proc_regioninfo>()]);
                    let last_pri = &*(&last_pri as *const _
                        as *const [u8; core::mem::size_of::<proc_regioninfo>()]);
                    pri == last_pri
                }
                && {
                    let last = self.cached_maps.last().unwrap();
                    last.1 % len == 0 && last.0 + last.1 == start
                }
            {
                self.cached_maps.last_mut().unwrap().1 += len;
            } else {
                self.cached_maps.push((start, len, perms));
            }

            start += len;
            core::mem::swap(&mut last_pri, &mut pri);
        }

        self.cached_maps.sort_by_key(|v| v.0);
    }
}

cglue_impl_group!(MacProcess, ProcessInstance, {});
cglue_impl_group!(MacProcess, IntoProcessInstance, {});

impl Process for MacProcess {
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
        self.update_cached_module_maps()?;

        self.cached_module_maps
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

        if self.cached_module_maps.is_empty() {
            self.update_cached_module_maps()?;
        }

        self.cached_module_maps
            .get(address.to_umem() as usize)
            .map(|map| {
                let path = map.2.as_str();

                ModuleInfo {
                    address,
                    parent_process: self.info.address,
                    base: map.0,
                    size: map.1,
                    name: path
                        .rsplit_once('/')
                        .or_else(|| path.rsplit_once('\\'))
                        .map(|v| v.1)
                        .unwrap_or(path)
                        .into(),
                    path: path.into(),
                    arch: self.info.sys_arch,
                }
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
        self.update_cached_maps(start, end);

        self.cached_maps
            .iter()
            .copied()
            .filter(|m| m.2 != PageType::NONE)
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
                    let diff = s - end;
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

impl MemoryView for MacProcess {
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

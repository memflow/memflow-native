#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxOs as NativeOs;

use memflow::cglue;
use memflow::os::root::*;
use memflow::prelude::v1::*;

cglue_impl_group!(NativeOs, OsInstance, {});

#[os_layer_bare(name = "native")]
pub fn build_kernel(
    _args: &Args,
    _: Option<ConnectorInstanceArcBox<'static>>,
    lib: COptArc<std::ffi::c_void>,
    log_level: log::Level,
) -> Result<OsInstanceArcBox<'static>> {
    simple_logger::SimpleLogger::new()
        .with_level(log_level.to_level_filter())
        .init()
        .ok();

    Ok(group_obj!((NativeOs::default(), lib) as OsInstance))
}

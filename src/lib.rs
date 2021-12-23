mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxOs as NativeOs;

use memflow::cglue;
use memflow::prelude::v1::*;

cglue_impl_group!(NativeOs, OsInstance, {});

#[os_layer_bare(name = "native")]
pub fn build_os(
    _args: &Args,
    _: Option<ConnectorInstanceArcBox<'static>>,
    lib: CArc<std::ffi::c_void>,
) -> Result<OsInstanceArcBox<'static>> {
    log::info!("Initialize native OS!");
    Ok(group_obj!((NativeOs::default(), lib) as OsInstance))
}

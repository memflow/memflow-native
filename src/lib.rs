#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxOs as NativeOs;

use memflow::prelude::v1::*;

#[os_layer_bare(name = "native")]
pub fn build_kernel(
    _args: &Args,
    _: Option<ConnectorInstance>,
    log_level: log::Level,
) -> Result<OsInstance> {
    simple_logger::SimpleLogger::new()
        .with_level(log_level.to_level_filter())
        .init()
        .ok();

    Ok(OsInstance::builder(NativeOs::default()).build())
}

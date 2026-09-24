use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Storage and file-sharing connectivity: SFTP/SMB/local connection
/// definitions, host-side share/mount provisioning, and validation --
/// a connection-and-share *provisioning layer* other Arsenals consume
/// (Reliquary first) rather than each implementing their own SFTP/SMB
/// configuration. See `crates/web/src/sepulchre/` and
/// `docs/sepulchre.md`.
pub struct SepulchreArsenal;

impl Arsenal for SepulchreArsenal {
    fn key(&self) -> &'static str {
        "sepulchre"
    }

    fn display_name(&self) -> &'static str {
        "Sepulchre"
    }

    fn description(&self) -> &'static str {
        "Storage and file-sharing connectivity."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::StorageConnectionsView]
    }
}

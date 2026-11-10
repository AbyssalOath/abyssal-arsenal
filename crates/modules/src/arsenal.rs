use abyssal_agent_protocol::Platforms;
use abyssal_core::{ModuleCategory, Permission};

/// The metadata contract every arsenal crate implements. Deliberately minimal:
/// there's no `routes()` hook yet because nothing needs one until a module has
/// a real page to serve. Adding that later is additive, not a breaking change
/// to any existing arsenal — this is what "add a module without rewriting
/// unrelated portions" means in practice.
pub trait Arsenal: Send + Sync {
    /// Stable identifier persisted in the `modules` table, e.g. `"cystoolbox"`.
    fn key(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> ModuleCategory;
    /// The permission(s) that gate viewing this arsenal's page. Empty means
    /// visible to any authenticated user.
    fn view_permissions(&self) -> &'static [Permission];
    /// The host operating systems this arsenal's host pages are for. Hosts
    /// on any other OS are left out of its picker and switcher, and its host
    /// pages redirect away from them. An arsenal with some actions per OS is
    /// `Both`; its pages hide the individual actions.
    fn platforms(&self) -> Platforms;
}

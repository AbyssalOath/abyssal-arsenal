use abyssal_modules::Arsenal;

/// Every arsenal the platform ships with, wired into the registry. Adding a
/// new arsenal crate means adding one line here (and to the workspace
/// manifest) — nothing else in `app` or `web` needs to change.
pub fn all() -> Vec<Box<dyn Arsenal>> {
    vec![
        Box::new(arsenal_cystoolbox::CystoolboxArsenal),
        Box::new(arsenal_cadavault::CadavaultArsenal),
        Box::new(arsenal_necrolink::NecrolinkArsenal),
        Box::new(arsenal_postmortem::PostmortemArsenal),
        Box::new(arsenal_reliquary::ReliquaryArsenal),
        Box::new(arsenal_mortiscope::MortiscopeArsenal),
        Box::new(arsenal_incarnation::IncarnationArsenal),
        Box::new(arsenal_resurrection::ResurrectionArsenal),
        Box::new(arsenal_necropsy::NecropsyArsenal),
        Box::new(arsenal_necropolis::NecropolisArsenal),
        Box::new(arsenal_obituary::ObituaryArsenal),
        Box::new(arsenal_reanimation::ReanimationArsenal),
        Box::new(arsenal_ossuary::OssuaryArsenal),
        Box::new(arsenal_catacomb::CatacombArsenal),
        Box::new(arsenal_parish::ParishArsenal),
        Box::new(arsenal_apothecary::ApothecaryArsenal),
        Box::new(arsenal_grimoire::GrimoireArsenal),
        Box::new(arsenal_cryptkeeper::CryptkeeperArsenal),
        Box::new(arsenal_defleshing::DefleshingArsenal),
        Box::new(arsenal_vivisection::VivisectionArsenal),
        Box::new(arsenal_inquest::InquestArsenal),
    ]
}

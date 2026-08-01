use crate::backend::PairingKind;

type KnownApp = (&'static str, &'static str);

const ALT: &str = "ALTPairingFile.mobiledevicepairing";
const LIVE_CONTAINER: &str = "SideStore/Documents/ALTPairingFile.mobiledevicepairing";
const PLIST: &str = "pairingFile.plist";

const LOCKDOWN: &[KnownApp] = &[
    ("Antrag", PLIST),
    ("EnsWilde", PLIST),
    ("Feather", PLIST),
    ("Ksign", PLIST),
    ("LiveContainer", LIVE_CONTAINER),
    ("Protokolle", PLIST),
    ("SideStore", ALT),
    ("SparseBox", PLIST),
    ("StikDebug", PLIST),
    ("StikDebug (Sideloaded)", PLIST),
    ("StikStore", PLIST),
];

const REMOTE: &[KnownApp] = &[
    ("Antrag", PLIST),
    ("Auto Capture", "rpPairingFile.plist"),
    ("Feather", PLIST),
    ("Ksign", PLIST),
    ("LiveContainer", LIVE_CONTAINER),
    ("Protokolle", PLIST),
    ("Reynard", PLIST),
    ("SideStore", ALT),
    ("StikDebug (Sideloaded)", PLIST),
    ("StosDebug", PLIST),
];

pub fn path(kind: PairingKind, name: &str) -> Option<&'static str> {
    let apps = match kind {
        PairingKind::Lockdown => LOCKDOWN,
        PairingKind::Remote => REMOTE,
    };
    apps.iter()
        .find_map(|(app, path)| (*app == name).then_some(*path))
}

//! `StateFlags` of an app manifest and the state derived from it (ADR 0012).
//!
//! The bit names follow the community-documented `EAppState` (open-steamworks, SteamKit);
//! Valve publishes no official table. [`StateFlags::state`] uses only the bits named here and
//! keeps every other bit without interpreting it.

use std::fmt;

/// The raw `StateFlags` bits of an `appmanifest_<appid>.acf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateFlags(u32);

impl StateFlags {
    /// `Uninstalled`.
    pub const UNINSTALLED: Self = Self(1);
    /// `UpdateRequired`.
    pub const UPDATE_REQUIRED: Self = Self(2);
    /// `FullyInstalled`.
    pub const FULLY_INSTALLED: Self = Self(4);
    /// `Encrypted`.
    pub const ENCRYPTED: Self = Self(8);
    /// `Locked`.
    pub const LOCKED: Self = Self(16);
    /// `FilesMissing`.
    pub const FILES_MISSING: Self = Self(32);
    /// `AppRunning`.
    pub const APP_RUNNING: Self = Self(64);
    /// `FilesCorrupt`.
    pub const FILES_CORRUPT: Self = Self(128);
    /// `UpdateRunning`.
    pub const UPDATE_RUNNING: Self = Self(256);
    /// `UpdatePaused`.
    pub const UPDATE_PAUSED: Self = Self(512);
    /// `UpdateStarted`.
    pub const UPDATE_STARTED: Self = Self(1024);
    /// `Uninstalling`.
    pub const UNINSTALLING: Self = Self(2048);
    /// `BackupRunning`.
    pub const BACKUP_RUNNING: Self = Self(4096);
    /// `Reconfiguring`.
    pub const RECONFIGURING: Self = Self(65_536);
    /// `Validating`.
    pub const VALIDATING: Self = Self(131_072);
    /// `AddingFiles`.
    pub const ADDING_FILES: Self = Self(262_144);
    /// `Preallocating`.
    pub const PREALLOCATING: Self = Self(524_288);
    /// `Downloading`.
    pub const DOWNLOADING: Self = Self(1_048_576);
    /// `Staging`.
    pub const STAGING: Self = Self(2_097_152);
    /// `Committing`.
    pub const COMMITTING: Self = Self(4_194_304);
    /// `UpdateStopping`.
    pub const UPDATE_STOPPING: Self = Self(8_388_608);

    /// Any of these makes the app [`AppState::NotInstalled`], even with `FullyInstalled`.
    pub const NOT_INSTALLED_ANY: Self = Self(
        Self::UNINSTALLED.0
            | Self::ENCRYPTED.0
            | Self::FILES_MISSING.0
            | Self::FILES_CORRUPT.0
            | Self::UNINSTALLING.0,
    );

    /// Any of these makes an installed app [`AppState::UpdatePending`].
    pub const UPDATE_ANY: Self = Self(
        Self::UPDATE_REQUIRED.0
            | Self::UPDATE_RUNNING.0
            | Self::UPDATE_PAUSED.0
            | Self::UPDATE_STARTED.0
            | Self::RECONFIGURING.0
            | Self::VALIDATING.0
            | Self::ADDING_FILES.0
            | Self::PREALLOCATING.0
            | Self::DOWNLOADING.0
            | Self::STAGING.0
            | Self::COMMITTING.0
            | Self::UPDATE_STOPPING.0,
    );

    /// The raw bits, as in the manifest.
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw bits, unknown ones included.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Every bit of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// At least one bit of `other` is set.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// The derived state (ADR 0012): not installed unless `FullyInstalled` is set and none of
    /// [`Self::NOT_INSTALLED_ANY`]; then update pending if any of [`Self::UPDATE_ANY`];
    /// otherwise installed. `AppRunning`, `Locked`, `BackupRunning` and unknown bits do not
    /// change it.
    pub const fn state(self) -> AppState {
        if !self.contains(Self::FULLY_INSTALLED) || self.intersects(Self::NOT_INSTALLED_ANY) {
            AppState::NotInstalled
        } else if self.intersects(Self::UPDATE_ANY) {
            AppState::UpdatePending
        } else {
            AppState::Installed
        }
    }
}

/// What detection makes of [`StateFlags`]. All apps are reported with their state; the
/// output layer decides what to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppState {
    /// Fully installed, no update pending.
    Installed,
    /// The files exist, but Steam is about to change them (update, validation, download).
    /// Phase 2 refuses to apply in this state.
    UpdatePending,
    /// Not (completely) installed, or the files are missing, corrupt or encrypted.
    NotInstalled,
}

impl fmt::Display for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Installed => "installed",
            Self::UpdatePending => "update pending",
            Self::NotInstalled => "not installed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, StateFlags as F};

    fn state(bits: u32) -> AppState {
        F::new(bits).state()
    }

    #[test]
    fn plain_states() {
        assert_eq!(state(0), AppState::NotInstalled);
        assert_eq!(state(4), AppState::Installed);
        // Steam writes 1026 (UpdateRequired | UpdateStarted) without FullyInstalled while a
        // first download runs.
        assert_eq!(state(1026), AppState::NotInstalled);
        assert_eq!(state(4 | 2), AppState::UpdatePending);
        assert_eq!(state(4 | 1024 | 2), AppState::UpdatePending);
    }

    #[test]
    fn every_not_installed_bit_wins_over_fully_installed() {
        for bit in [1, 8, 32, 128, 2048] {
            assert_eq!(state(4 | bit), AppState::NotInstalled, "{bit}");
            // Also together with an update bit.
            assert_eq!(state(4 | 2 | bit), AppState::NotInstalled, "{bit}");
        }
    }

    #[test]
    fn every_update_bit_makes_an_installed_app_pending() {
        for bit in [
            2, 256, 512, 1024, 65_536, 131_072, 262_144, 524_288, 1_048_576, 2_097_152, 4_194_304,
            8_388_608,
        ] {
            assert_eq!(state(4 | bit), AppState::UpdatePending, "{bit}");
            assert_eq!(state(bit), AppState::NotInstalled, "{bit}");
        }
    }

    #[test]
    fn running_locked_backup_and_unknown_bits_do_not_change_the_state() {
        let neutral = [
            16,
            64,
            4096,
            8192,
            16_384,
            32_768,
            1 << 24,
            1 << 30,
            1 << 31,
        ];
        for bit in neutral {
            assert_eq!(state(4 | bit), AppState::Installed, "{bit}");
            assert_eq!(state(4 | 2 | bit), AppState::UpdatePending, "{bit}");
            assert_eq!(state(bit), AppState::NotInstalled, "{bit}");
        }
        // Unknown bits are kept, never cleared.
        assert_eq!(F::new(u32::MAX).bits(), u32::MAX);
        assert_eq!(state(u32::MAX), AppState::NotInstalled);
    }

    #[test]
    fn the_masks_name_exactly_the_documented_bits() {
        assert_eq!(F::NOT_INSTALLED_ANY.bits(), 1 | 8 | 32 | 128 | 2048);
        assert_eq!(F::UPDATE_ANY.bits(), 2 | 256 | 512 | 1024 | 0x00FF_0000);
        // No bit is in both masks, and neither holds FullyInstalled or the neutral bits.
        assert!(!F::NOT_INSTALLED_ANY.intersects(F::UPDATE_ANY));
        for neutral in [
            F::FULLY_INSTALLED,
            F::LOCKED,
            F::APP_RUNNING,
            F::BACKUP_RUNNING,
        ] {
            assert!(!F::NOT_INSTALLED_ANY.intersects(neutral));
            assert!(!F::UPDATE_ANY.intersects(neutral));
        }
        assert!(F::new(6).contains(F::FULLY_INSTALLED));
        assert!(!F::new(6).contains(F::new(5)));
    }

    #[test]
    fn display() {
        assert_eq!(AppState::Installed.to_string(), "installed");
        assert_eq!(AppState::UpdatePending.to_string(), "update pending");
        assert_eq!(AppState::NotInstalled.to_string(), "not installed");
    }
}

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};

use crate::config::{ConfigStore, default_vault_root, project_root};
use crate::discovery::{Candidate, CandidateSet, DiscoveryRule, FoundVault, child_directories, probe};
use crate::doctor::{DoctorReport, run_doctor};
use crate::engine::Engine;
use crate::error::{ManagerError, Result};
use crate::fs_safe::ensure_vault_parent_directory;
use crate::host::{
    ConnectionPlan, Host, OpenCodeVersion, Scope, plan_connect_version, plan_disconnect,
};
use crate::model::{
    Durability, LaunchDescriptor, Profile, ProfileList, RemoveResult, validate_profile_name,
};

/// What `init` decided to do about the vault, and how it found it.
#[derive(Clone, Debug)]
pub struct VaultInit {
    pub status: &'static str,
    pub profile: Profile,
    pub launch: LaunchDescriptor,
    pub discovered_by: &'static str,
    pub discovered_detail: Option<String>,
    pub workspaces: usize,
    pub created: bool,
}

/// Forces one branch of the three-outcome decision. `Auto` is the default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultPolicy {
    Auto,
    /// Adopt the single candidate; refuse if there are zero or several.
    Adopt,
    /// Create; refuse if `--root` probes as a vault.
    Create,
}

#[derive(Clone, Debug)]
pub struct Manager {
    engine: Engine,
    config: ConfigStore,
}

impl Manager {
    pub fn resolve(engine: Option<&Path>) -> Result<Self> {
        Ok(Self {
            engine: Engine::resolve(engine)?,
            config: ConfigStore::resolve()?,
        })
    }

    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Discover an existing vault, adopt it, or create one -- and REFUSE rather
    /// than guess when several are reachable.
    ///
    /// The invariant this function exists to hold: `init-profile` is never
    /// called on a root that probes as a vault. `init-profile` on an existing
    /// vault does not fail -- it succeeds, adds a second workspace, and returns
    /// a profile whose every read and write answers "discover_active found
    /// corrupt state: current reference names an absent version". And the fork
    /// removes the recovery path: `profile import` then refuses because the
    /// vault has two workspaces. Measured 2026-08-26.
    pub fn init(
        &self,
        profile: &str,
        root: Option<&Path>,
        durability: Durability,
        policy: VaultPolicy,
        project: Option<&Path>,
    ) -> Result<VaultInit> {
        validate_profile_name(profile)?;
        if let Some(path) = root {
            if !path.is_absolute() {
                return Err(ManagerError::UnsafePath {
                    target: "vault root",
                    reason: "path must be absolute",
                });
            }
        }

        // Rule 2: an existing profile of this name IS the answer. This replaces
        // today's `profile already exists` / rc=2, which gave a user who ran
        // `init` twice no path forward.
        if let Ok(existing) = self.engine.profile_show(profile) {
            if let Some(requested) = root {
                let same = fs::canonicalize(requested)
                    .ok()
                    .zip(fs::canonicalize(&existing.root).ok())
                    .is_some_and(|(a, b)| a == b);
                if !same {
                    return Err(ManagerError::ProfileRootMismatch {
                        profile: profile.to_owned(),
                        existing: existing.root.display().to_string(),
                        requested: requested.display().to_string(),
                    });
                }
            }
            let workspaces = match probe(&existing.root) {
                Candidate::Vault { workspaces, .. } => workspaces,
                Candidate::NotAVault => 0,
            };
            let launch = self.publish(profile)?;
            return Ok(VaultInit {
                status: "already_initialized",
                profile: existing,
                launch,
                discovered_by: "existing profile",
                discovered_detail: Some(profile.to_owned()),
                workspaces,
                created: false,
            });
        }

        let candidates = self.discover(profile, root, project)?;

        match (policy, candidates.len()) {
            (VaultPolicy::Create, _) => {
                // The one case where the user asked for the destructive thing.
                let target = root.map_or_else(
                    || default_vault_root(profile),
                    |path| Ok(path.to_path_buf()),
                )?;
                self.create(profile, &target, durability, root.is_none())
            }
            (VaultPolicy::Adopt, 1) | (VaultPolicy::Auto, 1) => {
                let found = candidates.into_iter().next().expect("one candidate");
                self.adopt(profile, &found, durability)
            }
            (VaultPolicy::Adopt, count) => Err(ManagerError::Usage(format!(
                "--adopt requires exactly one discovered vault; {count} were found. Name the one you mean with --root."
            ))),
            (VaultPolicy::Auto, 0) => {
                let target = root.map_or_else(
                    || default_vault_root(profile),
                    |path| Ok(path.to_path_buf()),
                )?;
                self.create(profile, &target, durability, root.is_none())
            }
            (VaultPolicy::Auto, _) => Err(ManagerError::AmbiguousVault(ambiguous_message(
                profile,
                &candidates,
            ))),
        }
    }

    /// Rules 1 and 3-6 of the search order. Rule 2 (an existing profile of the
    /// requested name) is decided before this runs, because it is not a
    /// candidate -- it is the answer.
    fn discover(
        &self,
        profile: &str,
        root: Option<&Path>,
        project: Option<&Path>,
    ) -> Result<Vec<FoundVault>> {
        let mut set = CandidateSet::new();

        // Rule 1: --root given. Exactly one candidate; never search anything else.
        if let Some(path) = root {
            set.offer(DiscoveryRule::ExplicitRoot, None, path);
            return Ok(set.into_found());
        }

        // Rule 3: roots of every other registered profile.
        if let Ok(list) = self.engine.profile_list() {
            for name in &list.profiles {
                if name == profile {
                    continue;
                }
                if let Ok(other) = self.engine.profile_show(name) {
                    set.offer(
                        DiscoveryRule::RegisteredProfile,
                        Some(name.clone()),
                        &other.root,
                    );
                }
            }
        }

        // Rule 4: the manager's default vault root for this profile.
        let default_root = default_vault_root(profile)?;
        set.offer(DiscoveryRule::DefaultRoot, None, &default_root);

        // Rule 5: the project-local convention.
        if let Ok(project) = project_root(project) {
            set.offer(
                DiscoveryRule::ProjectLocal,
                None,
                &project.join(".kaleidoscope"),
            );
        }

        // Rule 6: every immediate child of the user-level vault directory.
        if let Some(vaults) = default_root.parent() {
            for child in child_directories(vaults)? {
                set.offer(DiscoveryRule::UserVaultDirectory, None, &child);
            }
        }

        Ok(set.into_found())
    }

    fn adopt(&self, profile: &str, found: &FoundVault, durability: Durability) -> Result<VaultInit> {
        let imported = self.engine.profile_import(profile, &found.root, durability)?;
        let launch = self.publish(profile)?;
        Ok(VaultInit {
            status: "adopted",
            profile: imported,
            launch,
            discovered_by: found.rule.as_str(),
            discovered_detail: found.detail.clone(),
            workspaces: found.workspaces,
            created: false,
        })
    }

    fn create(
        &self,
        profile: &str,
        root: &Path,
        durability: Durability,
        uses_default_root: bool,
    ) -> Result<VaultInit> {
        // The invariant, enforced at run time and not only by a debug assert:
        // `init-profile` must NEVER be called on a root that probes as a Vault.
        if let Candidate::Vault { workspaces, .. } = probe(root) {
            return Err(ManagerError::WouldForkVault {
                root: root.display().to_string(),
                workspaces,
            });
        }
        debug_assert!(matches!(probe(root), Candidate::NotAVault));
        if uses_default_root && durability == Durability::ProcessLocal {
            ensure_vault_parent_directory(root)?;
        }
        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let initialized = self
            .engine
            .init_profile(profile, root, &created_at, durability)?;
        if let Err(cause) = self.config.set_active_profile(Some(profile)) {
            return Err(ManagerError::InitManagerStateRecovery {
                profile: profile.to_owned(),
                cause: cause.to_string(),
            });
        }
        let workspaces = match probe(&initialized.profile.root) {
            Candidate::Vault { workspaces, .. } => workspaces,
            Candidate::NotAVault => 0,
        };
        Ok(VaultInit {
            status: "initialized",
            profile: initialized.profile,
            launch: initialized.launch,
            discovered_by: if uses_default_root {
                "default root"
            } else {
                "--root"
            },
            discovered_detail: None,
            workspaces,
            created: true,
        })
    }

    fn publish(&self, profile: &str) -> Result<LaunchDescriptor> {
        if let Err(cause) = self.config.set_active_profile(Some(profile)) {
            return Err(ManagerError::InitManagerStateRecovery {
                profile: profile.to_owned(),
                cause: cause.to_string(),
            });
        }
        self.engine.profile_launch(profile)
    }

    pub fn profile_list(&self) -> Result<ProfileList> {
        self.engine.profile_list()
    }

    pub fn profile_show(&self, name: &str) -> Result<Profile> {
        self.engine.profile_show(name)
    }

    pub fn profile_use(&self, name: &str) -> Result<()> {
        self.engine.profile_show(name)?;
        self.config.set_active_profile(Some(name))?;
        Ok(())
    }

    pub fn profile_remove(&self, name: &str) -> Result<RemoveResult> {
        let removed = self.engine.profile_remove(name)?;
        self.config.forget_profile(name)?;
        Ok(removed)
    }

    pub fn selected_profile(&self, explicit: Option<&str>) -> Result<String> {
        self.config.selected_profile(explicit)
    }

    pub fn config_descriptor(&self, explicit: Option<&str>) -> Result<(String, LaunchDescriptor)> {
        let profile = self.selected_profile(explicit)?;
        let descriptor = self.engine.profile_launch(&profile)?;
        Ok((profile, descriptor))
    }

    pub fn plan_connect(
        &self,
        host: Host,
        scope: Scope,
        explicit_profile: Option<&str>,
        project: Option<&Path>,
        open_code_version: Option<OpenCodeVersion>,
    ) -> Result<ConnectionPlan> {
        let (profile, descriptor) = self.config_descriptor(explicit_profile)?;
        plan_connect_version(
            host,
            scope,
            &profile,
            &descriptor,
            project,
            open_code_version,
        )
    }

    pub fn plan_disconnect(
        &self,
        host: Host,
        scope: Scope,
        project: Option<&Path>,
    ) -> Result<ConnectionPlan> {
        plan_disconnect(host, scope, project)
    }

    #[must_use]
    pub fn doctor(&self, project: Option<&Path>) -> DoctorReport {
        run_doctor(&self.engine, &self.config, project)
    }

    pub fn default_root(&self, profile: &str) -> Result<PathBuf> {
        default_vault_root(profile)
    }
}

/// The several-candidate refusal. It prints every candidate, in discovery
/// order, with the rule that found it, its absolute root and its workspace
/// count -- because "several were found" without saying which ones leaves the
/// user stuck, and a refusal that does not say what would work invites a guess.
fn ambiguous_message(profile: &str, candidates: &[FoundVault]) -> String {
    let mut message = String::from(
        "several Kaleidoscope vaults were found and none of them is the\nobvious one. Re-run with the one you mean:\n\n",
    );
    let _ = writeln!(
        message,
        "  kaleidoscope init --root /abs/path/to/the/vault --profile {profile}\n"
    );
    for found in candidates {
        let rule = found.detail.as_ref().map_or_else(
            || format!("found via {}", found.rule.as_str()),
            |detail| format!("found via {} '{detail}'", found.rule.as_str()),
        );
        let _ = writeln!(
            message,
            "  {:<38} {} workspace(s)  {}",
            rule,
            found.workspaces,
            found.root.display()
        );
    }
    message.push_str("\nNothing was created and nothing was changed.");
    message
}

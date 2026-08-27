use std::env;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr as _;

use kaleidoscope_manager::Manager;
use kaleidoscope_manager::account::AccountError;
#[cfg(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
use kaleidoscope_manager::account::{
    AccountClient, AccountClientConfig, BrowserLinkInteraction, ConsoleDeviceInteraction,
    DeviceDisplay, DevicePlatform, FileRefreshLock, LocalLogoutPolicy, LogoutScope,
    NativeCredentialStore, NativeHttpsTransport, NativeLoopbackInteraction, SystemRuntime,
};
use kaleidoscope_manager::config::{ConfigStore, profile_summary};
use kaleidoscope_manager::error::{ManagerError, Result};
#[cfg(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
use kaleidoscope_manager::fs_safe::ensure_parent_directory;
use kaleidoscope_manager::hooks::{
    SessionStartOptions, plan_install as plan_hook_install, plan_remove as plan_hook_remove,
    session_start_output,
};
use kaleidoscope_manager::host::{Host, OpenCodeVersion, Scope};
use kaleidoscope_manager::instructions::{
    InstructionTarget, plan_install as plan_instruction_install,
    plan_remove as plan_instruction_remove,
};
use kaleidoscope_manager::manager::VaultPolicy;
use kaleidoscope_manager::model::Durability;
use serde::Serialize;
#[cfg(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
use url::Url;
use uuid::Uuid;

const USAGE: &str = "\
Kaleidoscope public local manager

Usage:
  kaleidoscope [--engine PATH] init [--root PATH] [--profile NAME]
                                      [--durability process-local|durable-local]
                                      [--host HOST]... [--scope user|project]
                                      [--project PATH]
                                      [--opencode-version stable-v1|beta-v2]
                                      [--no-connect] [--no-instructions]
                                      [--no-skill] [--no-hooks]
                                      [--adopt | --create] [--dry-run] [--yes]
  kaleidoscope [--engine PATH] teardown [--host HOST]... [--scope user|project]
                                      [--project PATH] [--force] [--dry-run] [--yes]
  kaleidoscope [--engine PATH] hook session-start [--profile NAME] [--no-memories]
  kaleidoscope [--engine PATH] profile list
  kaleidoscope [--engine PATH] profile show NAME
  kaleidoscope [--engine PATH] profile use NAME
  kaleidoscope [--engine PATH] profile remove NAME
  kaleidoscope profile account show [NAME]
  kaleidoscope profile account bind ACCOUNT_UUID [NAME]
  kaleidoscope profile account unbind [NAME]
  kaleidoscope [--engine PATH] config [--profile NAME] [--json]
  kaleidoscope [--engine PATH] connect HOST [--scope user|project]
                                      [--profile NAME] [--project PATH]
                                      [--opencode-version stable-v1|beta-v2]
                                      [--dry-run] [--yes]
  kaleidoscope [--engine PATH] disconnect HOST [--scope user|project]
                                      [--project PATH] [--dry-run] [--yes]
  kaleidoscope instructions install TARGET [--host HOST] [--project PATH]
                                      [--force] [--dry-run] [--yes]
  kaleidoscope instructions remove TARGET [--host HOST] [--project PATH]
                                      [--force] [--dry-run] [--yes]
  kaleidoscope [--engine PATH] doctor [--project PATH] [--json]
  kaleidoscope login [--device]
  kaleidoscope status [--json]
  kaleidoscope logout [--all-devices] [--local-only]
  kaleidoscope account link PROVIDER
  kaleidoscope account identities
  kaleidoscope account unlink EXTERNAL_IDENTITY_UUID
  kaleidoscope account revoke-session
  kaleidoscope devices list
  kaleidoscope devices revoke DEVICE_UUID
  kaleidoscope --version

Instruction TARGET is skill, agents, claude, or cursor. `skill` requires
--host, because the skill directory differs per harness and defaulting is what
put the file where Claude Code does not read it.

`init` with no --host does profile work only. With --host it chains:
discover-or-adopt the vault, connect, install instructions, install the skill,
install the hook. `teardown` reverses those four in reverse order. Neither
touches the vault or the profile: data removal is `profile remove` plus
`kscope vault-delete`, deliberately separate verbs.
The manager edits host configuration only after preview and confirmation.

USER SCOPE IS THE DEFAULT. The MCP entry and the SessionStart hook go under
your home directory, so they are visible from any directory -- including a git
worktree and a temporary clone, which is where an agent harness usually puts
your work and where a project-scoped entry is not read at all. `--scope
project` puts them in the project instead. Instructions and the skill are
ALWAYS written to the project: git is what carries them into a worktree or a
clone, and a home-wide CLAUDE.md would inject Kaleidoscope into every unrelated
project you ever open.

PROJECT-SCOPED FILES GO TO THE PROJECT ROOT, not the working directory. The
root is resolved by the engine (`kscope where --root-only`), which walks up for
a marker; `--project PATH` overrides it.

Use --dry-run for an effect-free plan.

Exit codes: 0 success (including every documented no-op), 2 any refusal --
usage, conflict, IO, engine, cancellation -- and 3 `doctor` completing with at
least one check reporting an issue.
";

/// THREE exit codes, and deliberately only three.
///
/// 0 for success, including every documented no-op (`AlreadyConnected`,
/// `AlreadyRemoved`, `AlreadyInstalled`, `unchanged`) and profile-only `init`.
/// 2 for every `ManagerError` -- usage, conflict, refusal, IO, engine,
/// cancellation. 3 for `doctor` completing with at least one issue.
///
/// A per-category table (usage=2, conflict=3, io=4 ...) was considered and
/// rejected. Every refusal in this crate already exits 2, the 21-scenario
/// regression harness records `init_rc` and asserts 2 for the refusal
/// scenarios, and re-coding them buys a caller nothing it cannot already get
/// from the JSON `status` and `detail` fields it receives. The requirement is
/// NON-ZERO, and 2 satisfies it; churning it would invalidate a passing
/// baseline for no measured benefit.
///
/// `doctor` is the one genuine addition, because "the report says there are
/// issues" and "the command could not run" were indistinguishable before:
/// `doctor` printed `status: "issues"` and exited 0.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(ManagerError::DoctorIssues(count)) => {
            eprintln!("kaleidoscope: doctor found {count} issue(s)");
            ExitCode::from(3)
        }
        Err(error) => {
            eprintln!("kaleidoscope: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<()> {
    let mut arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.is_empty() || matches!(arguments[0].as_str(), "-h" | "--help") {
        print!("{USAGE}");
        return Ok(());
    }
    if matches!(arguments[0].as_str(), "-V" | "--version") {
        println!("kaleidoscope {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let engine = take_path_option(&mut arguments, "--engine")?;
    let command = arguments
        .first()
        .cloned()
        .ok_or_else(|| ManagerError::Usage(USAGE.to_owned()))?;
    arguments.remove(0);
    if command == "instructions" {
        return run_instructions(engine.as_deref(), arguments);
    }
    if command == "hook" {
        return run_hook(engine.as_deref(), arguments);
    }
    if matches!(
        command.as_str(),
        "login" | "status" | "logout" | "account" | "devices"
    ) {
        return run_account(parse_account_invocation(&command, arguments)?);
    }
    if command == "profile" && arguments.first().is_some_and(|value| value == "account") {
        return run_profile_account(arguments);
    }
    let manager = Manager::resolve(engine.as_deref())?;
    match command.as_str() {
        "init" => run_init(&manager, engine.as_deref(), arguments),
        "profile" => run_profile(&manager, arguments),
        "config" => run_config(&manager, arguments),
        "connect" => run_connection(&manager, engine.as_deref(), true, arguments),
        "disconnect" => run_connection(&manager, engine.as_deref(), false, arguments),
        "teardown" => run_teardown(&manager, engine.as_deref(), arguments),
        "doctor" => run_doctor(&manager, engine.as_deref(), arguments),
        _ => Err(ManagerError::Usage(USAGE.to_owned())),
    }
}

enum AccountInvocation {
    Login { device: bool },
    Status,
    Logout { all_devices: bool, local_only: bool },
    Link { provider: String },
    Identities,
    Unlink { external_identity_id: Uuid },
    RevokeSession,
    Devices,
    RevokeDevice { device_id: Uuid },
}

fn parse_account_invocation(
    command: &str,
    mut arguments: Vec<String>,
) -> Result<AccountInvocation> {
    match command {
        "login" => {
            let device = take_flag(&mut arguments, "--device");
            require_empty(&arguments)?;
            Ok(AccountInvocation::Login { device })
        }
        "status" => {
            let _json = take_flag(&mut arguments, "--json");
            require_empty(&arguments)?;
            Ok(AccountInvocation::Status)
        }
        "logout" => {
            let all_devices = take_flag(&mut arguments, "--all-devices");
            let local_only = take_flag(&mut arguments, "--local-only");
            if all_devices && local_only {
                return Err(ManagerError::Usage(
                    "--all-devices cannot be combined with --local-only".to_owned(),
                ));
            }
            require_empty(&arguments)?;
            Ok(AccountInvocation::Logout {
                all_devices,
                local_only,
            })
        }
        "account" => {
            let action = arguments.first().cloned().ok_or_else(|| {
                ManagerError::Usage(
                    "account requires link, identities, unlink, or revoke-session".to_owned(),
                )
            })?;
            arguments.remove(0);
            match action.as_str() {
                "link" => Ok(AccountInvocation::Link {
                    provider: one_argument(arguments, "account link requires PROVIDER")?,
                }),
                "identities" => {
                    require_empty(&arguments)?;
                    Ok(AccountInvocation::Identities)
                }
                "unlink" => {
                    let value =
                        one_argument(arguments, "account unlink requires EXTERNAL_IDENTITY_UUID")?;
                    let external_identity_id = Uuid::parse_str(&value).map_err(|_| {
                        ManagerError::Usage(
                            "account unlink requires a valid external identity UUID".to_owned(),
                        )
                    })?;
                    Ok(AccountInvocation::Unlink {
                        external_identity_id,
                    })
                }
                "revoke-session" => {
                    require_empty(&arguments)?;
                    Ok(AccountInvocation::RevokeSession)
                }
                _ => Err(ManagerError::Usage(
                    "account requires link, identities, unlink, or revoke-session".to_owned(),
                )),
            }
        }
        "devices" => {
            let action = arguments
                .first()
                .cloned()
                .ok_or_else(|| ManagerError::Usage("devices requires list or revoke".to_owned()))?;
            arguments.remove(0);
            match action.as_str() {
                "list" => {
                    require_empty(&arguments)?;
                    Ok(AccountInvocation::Devices)
                }
                "revoke" => {
                    let value = one_argument(arguments, "devices revoke requires DEVICE_UUID")?;
                    let device_id = Uuid::parse_str(&value).map_err(|_| {
                        ManagerError::Usage(
                            "devices revoke requires a valid device UUID".to_owned(),
                        )
                    })?;
                    Ok(AccountInvocation::RevokeDevice { device_id })
                }
                _ => Err(ManagerError::Usage(
                    "devices requires list or revoke".to_owned(),
                )),
            }
        }
        _ => Err(ManagerError::Usage(USAGE.to_owned())),
    }
}

#[cfg(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
#[allow(clippy::too_many_lines)]
fn run_account(invocation: AccountInvocation) -> Result<()> {
    let client = native_account_client()?;
    match invocation {
        AccountInvocation::Login { device } => {
            let display = DeviceDisplay {
                product_name: "Kaleidoscope".to_owned(),
                device_label: "Kaleidoscope CLI device".to_owned(),
                platform: DevicePlatform::current().ok_or(AccountError::ProviderNotConfigured)?,
                application_version: env!("CARGO_PKG_VERSION").to_owned(),
            };
            if device {
                print_json(&client.login_device(&ConsoleDeviceInteraction, &display)?)
            } else {
                print_json(&client.login_pkce(&NativeLoopbackInteraction::default(), &display)?)
            }
        }
        AccountInvocation::Status => print_json(&client.status()?),
        AccountInvocation::Logout {
            all_devices,
            local_only,
        } => {
            if local_only {
                eprintln!(
                    "warning: local-only logout does not revoke the remote session; revoke it from the account web UI"
                );
            }
            print_json(&client.logout(
                if all_devices {
                    LogoutScope::AllDevices
                } else {
                    LogoutScope::CurrentSession
                },
                if local_only {
                    LocalLogoutPolicy::ConfirmedLocalOnly
                } else {
                    LocalLogoutPolicy::RequireRemoteRevocation
                },
            )?)
        }
        AccountInvocation::Link { provider } => {
            print_json(&client.link(&provider, &BrowserLinkInteraction)?)
        }
        AccountInvocation::Identities => print_json(&client.external_identities()?),
        AccountInvocation::Unlink {
            external_identity_id,
        } => print_json(&client.unlink(external_identity_id)?),
        AccountInvocation::RevokeSession => print_json(&client.logout(
            LogoutScope::CurrentSession,
            LocalLogoutPolicy::RequireRemoteRevocation,
        )?),
        AccountInvocation::Devices => print_json(&client.devices()?),
        AccountInvocation::RevokeDevice { device_id } => {
            print_json(&client.revoke_device(device_id)?)
        }
    }
}

#[cfg(not(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
)))]
fn run_account(invocation: AccountInvocation) -> Result<()> {
    match invocation {
        AccountInvocation::Login { device } => {
            let _ = device;
        }
        AccountInvocation::Logout {
            all_devices,
            local_only,
        } => {
            let _ = (all_devices, local_only);
        }
        AccountInvocation::Link { provider } => drop(provider),
        AccountInvocation::Identities => {}
        AccountInvocation::Unlink {
            external_identity_id,
        } => {
            let _ = external_identity_id;
        }
        AccountInvocation::RevokeDevice { device_id } => {
            let _ = device_id;
        }
        AccountInvocation::Status
        | AccountInvocation::RevokeSession
        | AccountInvocation::Devices => {}
    }
    Err(AccountError::ProviderNotConfigured.into())
}

#[cfg(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn native_account_client() -> Result<
    AccountClient<NativeHttpsTransport, NativeCredentialStore, FileRefreshLock, SystemRuntime>,
> {
    let config = account_config_from_environment()?;
    let transport = NativeHttpsTransport::new(&config)?;
    let lock_path = ConfigStore::resolve()?
        .path()
        .with_file_name("account-refresh.lock");
    ensure_parent_directory(&lock_path)?;
    let lock = FileRefreshLock::new(lock_path)?;
    AccountClient::new(
        config,
        transport,
        NativeCredentialStore::new(),
        lock,
        SystemRuntime,
    )
    .map_err(Into::into)
}

#[cfg(all(
    feature = "native-account-http",
    feature = "native-credential-store",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn account_config_from_environment() -> Result<AccountClientConfig> {
    let setting = |name: &str| {
        env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(AccountError::ProviderNotConfigured)
    };
    let account_origin = Url::parse(&setting("KALEIDOSCOPE_ACCOUNT_ORIGIN")?)
        .map_err(|_| AccountError::InvalidConfiguration("account origin is not a valid URL"))?;
    let issuer = Url::parse(&setting("KALEIDOSCOPE_ACCOUNT_ISSUER")?)
        .map_err(|_| AccountError::InvalidConfiguration("issuer is not a valid URL"))?;
    AccountClientConfig::new(
        account_origin,
        issuer,
        setting("KALEIDOSCOPE_ACCOUNT_AUDIENCE")?,
        setting("KALEIDOSCOPE_ACCOUNT_CLIENT_ID")?,
        "/oauth/callback".to_owned(),
    )
    .map_err(Into::into)
}

fn run_instructions(engine: Option<&std::path::Path>, mut arguments: Vec<String>) -> Result<()> {
    if arguments.len() < 2 {
        return Err(ManagerError::Usage(
            "instructions requires install|remove and skill|agents|claude|cursor".to_owned(),
        ));
    }
    let action = arguments.remove(0);
    let target = InstructionTarget::from_str(&arguments.remove(0))?;
    let host = take_string_option(&mut arguments, "--host")?
        .map_or(Ok(None), |value| Host::from_str(&value).map(Some))?;
    let explicit_project = take_path_option(&mut arguments, "--project")?;
    let force = take_flag(&mut arguments, "--force");
    let dry_run = take_flag(&mut arguments, "--dry-run");
    let yes = take_flag(&mut arguments, "--yes");
    require_empty(&arguments)?;
    // The one command that can reach the no-engine fallback: it is the only
    // verb here that does not already hard-require an engine.
    let resolved = resolve_project_directory(engine, explicit_project.as_deref())?;
    let project = Some(resolved.directory.as_path());
    let plan = match action.as_str() {
        "install" => plan_instruction_install(target, host, project, force)?,
        "remove" | "uninstall" => plan_instruction_remove(target, host, project, force)?,
        _ => {
            return Err(ManagerError::Usage(
                "instructions action must be install or remove".to_owned(),
            ));
        }
    };
    eprintln!("{}", plan.preview());
    if let Some(discarded) = &plan.discarded {
        eprintln!(
            "\n--force will DISCARD these bytes from {}:\n{discarded}",
            plan.target.display()
        );
    }
    if dry_run {
        return print_json(&plan.summary(true));
    }
    if !plan.is_noop() && !yes {
        confirm()?;
    }
    plan.apply()?;
    print_json(&plan.summary(false))
}

/// The hook body. Invoked BY the harness, not by users.
///
/// EXITS 0 ON EVERY PATH once the action is `session-start`, including every
/// failure path -- a hook that exits non-zero is a hook the user turns off, and
/// a broken memory configuration should be visible in the session rather than
/// fatal to it.
///
/// That was NOT true before. `--profile` with no value, an unrecognised extra
/// argument, and an unreadable stdin each returned `Err` from here, which
/// `main` turns into exit 2 -- so the one invocation shape the harness runs was
/// one typo in a settings file away from a hook the user is told is broken.
/// Everything after the action check is now absorbed and REPORTED instead, and
/// `the_hook_exits_zero_when_every_stage_fails` pins it.
///
/// The action check itself still refuses, because `kaleidoscope hook whatever`
/// is a person mistyping at a terminal, not the harness.
fn run_hook(engine: Option<&std::path::Path>, mut arguments: Vec<String>) -> Result<()> {
    let action = arguments
        .first()
        .cloned()
        .ok_or_else(|| ManagerError::Usage("hook requires session-start".to_owned()))?;
    if action != "session-start" {
        return Err(ManagerError::Usage(
            "hook requires session-start".to_owned(),
        ));
    }
    arguments.remove(0);
    let retrieval = !take_flag(&mut arguments, "--no-memories")
        && env::var("KALEIDOSCOPE_HOOK_MEMORIES").ok().as_deref() != Some("0");
    let profile = take_string_option(&mut arguments, "--profile")
        .ok()
        .flatten()
        .unwrap_or_else(|| "default".to_owned());
    // Unrecognised arguments are noted in the emitted context rather than
    // refused. The harness's own entry never carries any; a person's might.
    let unexpected = arguments.join(" ");

    // The SESSION's working directory, from the harness's documented hook input
    // on stdin, and only then the hook process's own. They are not reliably the
    // same, and the wrong one retrieves for the wrong project.
    let input = kaleidoscope_manager::hooks::read_hook_input();
    let cwd = input
        .as_ref()
        .and_then(|value| value["cwd"].as_str())
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_dir())
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // `Manager::resolve` also opens the config store; the hook only needs the
    // engine, and it must not fail if the config store is unreadable.
    // The Result is KEPT, not `.ok()`-ed: `session_start_output` interpolates
    // the reason, and discarding it here is what made an engine that was found
    // and rejected read as an engine that was not installed.
    let resolved = kaleidoscope_manager::engine::Engine::resolve(engine);
    let options = SessionStartOptions {
        profile,
        cwd,
        retrieval,
    };
    println!("{}", session_start_output(resolved.as_ref(), &options));
    if !unexpected.is_empty() {
        eprintln!("kaleidoscope: hook session-start ignored unexpected argument(s): {unexpected}");
    }
    Ok(())
}

/// The project directory this invocation writes project-scoped files into,
/// with the provenance of the answer.
///
/// RESOLVED ONCE PER INVOCATION, in `main.rs`, and threaded into every existing
/// `explicit_project` parameter. No signature below `main.rs` changes, and
/// `config::project_root` keeps its working-directory fallback for the library
/// API -- which the CLI now never reaches.
struct ProjectDirectory {
    directory: PathBuf,
    /// `explicit` | `project_marker` | `repository_default` |
    /// `vault_ancestor` | `working_directory_default` | `no_engine_fallback`
    source: String,
    marker: Option<String>,
    repository: Option<PathBuf>,
    differs_from_cwd: bool,
}

impl ProjectDirectory {
    fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "directory": self.directory,
            "source": self.source,
            "marker": self.marker,
            "repository": self.repository,
            "differs_from_cwd": self.differs_from_cwd,
        })
    }

    /// Said on stderr, before the first preview, when the answer is not the
    /// obvious one. A user who ran `init` in `src/deep` and finds no
    /// `.mcp.json` there has no way to tell a bug from a feature otherwise.
    fn announce(&self) {
        // Nothing to announce for `--project`: the user typed the path, so the
        // line would restate their own argument back at them on every run.
        if self.source == "explicit" {
            return;
        }
        if self.differs_from_cwd {
            let how = self.marker.as_ref().map_or_else(
                || format!("found by the {} rule", self.source),
                |marker| format!("found by {marker}"),
            );
            eprintln!(
                "kaleidoscope: project root is {} ({how}), not the current directory. Project-scoped files go there.",
                self.directory.display()
            );
        }
        if let Some(repository) = self.repository.as_ref() {
            if repository != &self.directory {
                eprintln!(
                    "kaleidoscope: this is a linked worktree of {}; project-scoped files go into the worktree, and the worktree is deleted when the branch is. --scope user (the default) is not affected.",
                    repository.display()
                );
            }
        }
    }
}

/// Where a project-scoped file belongs, asked of the engine rather than guessed.
///
/// **The manager does not walk the filesystem.** `src/config.rs` used to answer
/// "explicit path, or cwd", so running `init` two directories below a
/// `CLAUDE.md` wrote `.mcp.json`, `CLAUDE.md`, `SKILL.md` and
/// `.claude/settings.json` into `src/deep`. The engine already owns that walk;
/// `engine::Engine::resolved_project` says why a second copy here would be
/// worse than a round trip.
///
/// FOUR CASES, in order:
///
///  1. `--project PATH` -- taken, no engine call at all.
///  2. engine present and answering -- its answer.
///  3. engine NOT INSTALLED -- the working directory, with a warning. Reachable
///     only from `instructions install|remove`; every other verb here resolves
///     a `Manager` first and so has already failed on a missing engine.
///  4. engine present but the call FAILED -- refuse. Falling back here would
///     silently reintroduce exactly the defect being fixed, in the one case
///     where the user has an engine and could reasonably expect it to be used.
fn resolve_project_directory(
    engine: Option<&std::path::Path>,
    explicit: Option<&std::path::Path>,
) -> Result<ProjectDirectory> {
    let working_directory =
        env::current_dir().map_err(|error| ManagerError::io("resolve working directory", error))?;
    let canonical_cwd = kaleidoscope_manager::config::project_root(Some(&working_directory))?;
    if let Some(path) = explicit {
        let directory = kaleidoscope_manager::config::project_root(Some(path))?;
        let differs_from_cwd = directory != canonical_cwd;
        return Ok(ProjectDirectory {
            directory,
            source: "explicit".to_owned(),
            marker: None,
            repository: None,
            differs_from_cwd,
        });
    }
    let resolved = match kaleidoscope_manager::engine::Engine::resolve(engine) {
        Ok(engine) => engine.resolved_project(&working_directory),
        Err(ManagerError::EngineNotFound) => {
            eprintln!(
                "kaleidoscope: kscope is not installed, so the project root could not be resolved; using the working directory. Pass --project PATH to be explicit."
            );
            return Ok(ProjectDirectory {
                directory: canonical_cwd,
                source: "no_engine_fallback".to_owned(),
                marker: None,
                repository: None,
                differs_from_cwd: false,
            });
        }
        Err(error) => return Err(error),
    };
    // THE REMEDY COMES FIRST. It used to be appended after the engine's own
    // message, and when that message was the engine's entire usage text the
    // one sentence a user can act on sat at character 8,284 of 8,354.
    let resolved = resolved.map_err(|error| {
        ManagerError::Usage(format!(
            "kscope cannot report the project root, so nothing was written. Upgrade kscope to a build carrying `where --root-only`, or pass --project PATH. The engine said: {error}"
        ))
    })?;
    let directory = kaleidoscope_manager::config::project_root(Some(&resolved.project))?;
    let differs_from_cwd = directory != canonical_cwd;
    Ok(ProjectDirectory {
        directory,
        source: resolved.project_source,
        marker: resolved.project_marker,
        repository: resolved.repository,
        differs_from_cwd,
    })
}

/// Repeatable `--host`. `take_string_option` removes one occurrence, so
/// draining it in a loop collects all of them in the order they were written.
fn take_hosts(arguments: &mut Vec<String>) -> Result<Vec<Host>> {
    let mut hosts = Vec::new();
    while let Some(value) = take_string_option(arguments, "--host")? {
        let host = Host::from_str(&value)?;
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

#[allow(clippy::too_many_lines)]
fn run_init(
    manager: &Manager,
    engine: Option<&std::path::Path>,
    mut arguments: Vec<String>,
) -> Result<()> {
    let root = take_path_option(&mut arguments, "--root")?;
    let profile =
        take_string_option(&mut arguments, "--profile")?.unwrap_or_else(|| "default".to_owned());
    let durability = take_string_option(&mut arguments, "--durability")?
        .map_or(Ok(Durability::ProcessLocal), |value| {
            Durability::from_str(&value)
        })?;
    let hosts = take_hosts(&mut arguments)?;
    let requested_scope = take_string_option(&mut arguments, "--scope")?;
    let scope_source = if requested_scope.is_some() {
        "flag"
    } else {
        "default"
    };
    // USER SCOPE IS THE DEFAULT. Agent harnesses isolate work in worktrees and
    // temporary clones -- Claude Code creates worktrees natively -- and a
    // project-scoped entry is not read from either. Measured on this machine:
    // the main checkout had `.mcp.json` and the worktree the session was
    // actually running in had none, so the configuration written minutes
    // earlier did not reach the session that wrote it.
    let scope = requested_scope.map_or(Ok(Scope::User), |value| Scope::from_str(&value))?;
    let explicit_project = take_path_option(&mut arguments, "--project")?;
    let open_code_version = take_string_option(&mut arguments, "--opencode-version")?
        .map_or(Ok(None), |value| {
            OpenCodeVersion::from_str(&value).map(Some)
        })?;
    let no_connect = take_flag(&mut arguments, "--no-connect");
    let no_instructions = take_flag(&mut arguments, "--no-instructions");
    let no_skill = take_flag(&mut arguments, "--no-skill");
    let no_hooks = take_flag(&mut arguments, "--no-hooks");
    let adopt = take_flag(&mut arguments, "--adopt");
    let create = take_flag(&mut arguments, "--create");
    let dry_run = take_flag(&mut arguments, "--dry-run");
    let yes = take_flag(&mut arguments, "--yes");
    require_empty(&arguments)?;
    if adopt && create {
        return Err(ManagerError::Usage(
            "--adopt cannot be combined with --create".to_owned(),
        ));
    }
    let policy = if adopt {
        VaultPolicy::Adopt
    } else if create {
        VaultPolicy::Create
    } else {
        VaultPolicy::Auto
    };

    let resolved_project = resolve_project_directory(engine, explicit_project.as_deref())?;
    let project = Some(resolved_project.directory.as_path());
    resolved_project.announce();
    announce_scope(
        scope,
        scope_source,
        &resolved_project.directory,
        !hosts.is_empty(),
    );

    let initialized = manager.init(
        &profile,
        root.as_deref(),
        durability,
        policy,
        project,
        dry_run,
    )?;
    // The vault root is NOT printed. `profile_summary` redacts it deliberately
    // -- it is a vault coordinate, and the CLI's canary test asserts no
    // coordinate reaches stdout or a host config. The discovery rule is what
    // the operator actually needs: it says WHICH rule found the vault, without
    // naming the path.
    let mut steps = vec![serde_json::json!({
        "step": "profile",
        "status": initialized.status,
        "detail": format!(
            "{} via {}",
            if initialized.created { "created" } else { "reused" },
            initialized.discovered_by
        ),
    })];

    // `init` is atomic PER STEP, not overall. A step that fails leaves the
    // earlier steps applied, reports "issue" with the reason, exits 2, and
    // `next` names the teardown that undoes what did land. Rolling back a
    // successful connect because a hook failed is silently undoing a thing that
    // worked, which is worse than leaving it and saying so.
    let mut failure: Option<ManagerError> = None;
    if hosts.is_empty() {
        // rc STAYS 0 -- profile-only `init` is documented and useful -- but it
        // must SAY so. "I ran init and nothing got wired" is the shape of a
        // silent failure, and until now the command answered it with a success
        // report that mentioned no hosts at all.
        eprintln!(
            "kaleidoscope: no --host given, so this only created/adopted a profile. Nothing was wired.\n              Pass --host claude-code|codex|cursor|opencode to wire a harness."
        );
        steps.push(serde_json::json!({
            "step": "hosts",
            "status": "skipped",
            "detail": "no --host given",
        }));
    }

    // THE PRE-FLIGHT COMES FIRST, AND IT WORKS ON PATHS, NOT PLANS.
    //
    // Once user scope became the default, one `init` writes into TWO directory
    // trees, and a permission failure in the second left the first applied --
    // measured: the read-only-project scenario went from "rc=2, nothing
    // written" to "rc=2, the home-side entry written". Something has to prove
    // every target is writable before the first one is written.
    //
    // It CANNOT be done by building every plan up front. `--host codex --host
    // opencode` share `AGENTS.md`: the second plan snapshots the file, the
    // first plan's `apply` writes it, and the second then refuses with
    // `ConcurrentEdit` against a change the manager itself made. Plans are
    // built lazily, one host at a time, for exactly that reason. So the
    // pre-flight asks the question a plan is not needed for -- "can this
    // process create a file next to that target" -- from the PATHS the enabled
    // steps will use.
    //
    // It over-approximates: a step that turns out to be a no-op is still
    // probed. That is deliberate. The probe creates and removes one file in a
    // directory the command is about to write to anyway, and under-approximating
    // is what leaves half a configuration behind.
    if failure.is_none() && !dry_run {
        if let Err(error) = preflight(
            &hosts,
            scope,
            project,
            no_connect,
            no_instructions,
            no_skill,
            no_hooks,
        ) {
            steps.push(serde_json::json!({
                "step": "preflight",
                "status": "issue",
                "detail": error.to_string(),
            }));
            failure = Some(error);
        }
    }
    for host in &hosts {
        if failure.is_some() {
            break;
        }
        let host = *host;
        match host_steps(
            manager,
            host,
            scope,
            &profile,
            &initialized.launch,
            project,
            open_code_version,
            no_connect,
            no_instructions,
            no_skill,
            no_hooks,
        ) {
            Ok(plans) => {
                for (name, step) in plans {
                    match apply_step(step, dry_run, yes) {
                        Ok(mut value) => {
                            value["step"] = serde_json::json!(name);
                            value["host"] = serde_json::json!(host);
                            steps.push(value);
                        }
                        Err(error) => {
                            steps.push(serde_json::json!({
                                "step": name,
                                "host": host,
                                "status": "issue",
                                "detail": error.to_string(),
                            }));
                            failure = Some(error);
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                steps.push(serde_json::json!({
                    "step": "host",
                    "host": host,
                    "status": "issue",
                    "detail": error.to_string(),
                }));
                failure = Some(error);
            }
        }
    }

    let carryover = project_scope_carryover(scope, &hosts, project);
    steps.extend(carryover.iter().cloned());

    // REGISTER THE PROJECT, so a later teardown standing somewhere else knows
    // this tree exists. Only when instructions or a skill actually went in --
    // those are the project-anchored half, and they are what makes a
    // machine-wide entry load-bearing for a directory the teardown is not
    // standing in. Best effort: `init` has already succeeded by here, and a
    // config write that fails must not turn that into a failure.
    if !dry_run
        && failure.is_none()
        && !hosts.is_empty()
        && (!no_instructions || !no_skill)
        && kaleidoscope_manager::instructions::project_carries_instructions(
            &resolved_project.directory,
        )
    {
        if let Ok(store) = ConfigStore::resolve() {
            store.register_project(&resolved_project.directory);
        }
    }

    let mut next = vec!["kaleidoscope doctor --json".to_owned()];
    if hosts.is_empty() {
        next.push("kaleidoscope connect HOST --dry-run".to_owned());
    } else {
        for host in &hosts {
            next.push(format!(
                "kaleidoscope teardown --host {} --scope {} --dry-run",
                host.as_str(),
                scope.as_str()
            ));
        }
    }
    for step in &carryover {
        if let Some(remedy) = step.get("remedy").and_then(serde_json::Value::as_str) {
            next.push(remedy.to_owned());
        }
    }
    print_json(&serde_json::json!({
        // THE TOP-LEVEL STATUS IS THE COMMAND'S, NOT THE PROFILE'S.
        //
        // It used to be `initialized.status` unconditionally -- the vault/
        // profile outcome, blind to whether any host step failed -- so a
        // refused `init` printed `"status": "initialized"` on stdout while
        // exiting 2. Defect 1's complaint was that a script wrapping `init`
        // reads a refusal as success; fixing the exit code alone left that
        // true for every caller reading the JSON, which is the shape this
        // command itself promotes (`next: ["kaleidoscope doctor --json"]`).
        // `teardown` already degraded to "issues"; the two now agree.
        //
        // The profile outcome is not lost: it stays on the `profile` step,
        // where `adopted` vs `initialized` is a fact about the vault rather
        // than a verdict on the run.
        "status": if dry_run { "dry_run" } else if failure.is_some() { "issues" } else { initialized.status },
        "profile_status": initialized.status,
        "scope": scope,
        "scope_source": scope_source,
        // The half `--scope` does NOT govern, named so the user does not go
        // looking for their skill in the wrong tree. `instructions.rs` has no
        // `Scope` type at all: `--scope user` is a SPLIT, not a scope, and
        // saying so is cheaper than letting each user discover it.
        "scope_applies_to": ["connect", "hook"],
        "instructions_scope": "project",
        "project": resolved_project.report(),
        "profile": initialized.profile.as_ref().map_or_else(
            || serde_json::json!({"name": profile, "status": initialized.status, "detail": "dry run: no profile was created, so there is none to describe"}),
            profile_summary,
        ),
        "vault": {
            "discovered_by": initialized.discovered_by,
            "discovered_detail": initialized.discovered_detail,
            "workspaces": initialized.workspaces,
            "created": initialized.created,
        },
        "launch": initialized.launch,
        "launch_provisional": initialized.provisional_launch,
        "steps": steps,
        "hosts_available": Host::ALL.iter().map(|host| host.as_str()).collect::<Vec<_>>(),
        "next": next,
    }))?;
    failure.map_or(Ok(()), Err)
}

/// One applied step, as a summary value. Boxed because the four plan types are
/// different structs with the same three-method shape.
enum Step {
    Connection(Box<kaleidoscope_manager::host::ConnectionPlan>),
    Instruction(Box<kaleidoscope_manager::instructions::InstructionPlan>),
    Hook(Box<kaleidoscope_manager::hooks::HookPlan>),
    Skipped(&'static str),
}

/// Every file this invocation could write, before any of them is written.
///
/// Derived from PATHS rather than plans -- see the comment at the call site for
/// why plans cannot be built up front. A skipped step contributes nothing,
/// because refusing an `init --no-hooks` over an unwritable settings directory
/// would be refusing over a file the command was told not to touch.
#[allow(clippy::fn_params_excessive_bools)]
fn preflight(
    hosts: &[Host],
    scope: Scope,
    project: Option<&std::path::Path>,
    no_connect: bool,
    no_instructions: bool,
    no_skill: bool,
    no_hooks: bool,
) -> Result<()> {
    let home = kaleidoscope_manager::config::user_home()?;
    let project = match project {
        Some(project) => project.to_path_buf(),
        None => kaleidoscope_manager::config::project_root(None)?,
    };
    let mut targets: Vec<PathBuf> = Vec::new();
    for host in hosts {
        let host = *host;
        if !no_connect {
            targets.push(kaleidoscope_manager::host::host_config_path(
                host, scope, &home, &project,
            )?);
        }
        if !no_instructions {
            targets.push(kaleidoscope_manager::instructions::instruction_path(
                instruction_target_for(host),
                None,
                &project,
            )?);
        }
        if !no_skill && host != Host::Cursor {
            targets.push(kaleidoscope_manager::instructions::instruction_path(
                InstructionTarget::Skill,
                Some(host),
                &project,
            )?);
        }
        if !no_hooks && host == Host::ClaudeCode {
            targets.push(kaleidoscope_manager::hooks::settings_path(
                scope,
                Some(&project),
            )?);
        }
    }
    for target in targets {
        kaleidoscope_manager::fs_safe::assert_writable(&target)?;
    }
    Ok(())
}

/// Said before the first preview, because changing a default is a compatibility
/// event and the user who expected the old behaviour must see it immediately
/// rather than wonder where the file went.
fn announce_scope(scope: Scope, scope_source: &str, project: &std::path::Path, wiring: bool) {
    if !wiring {
        return;
    }
    let source = if scope_source == "default" {
        " (default)"
    } else {
        ""
    };
    eprintln!("kaleidoscope: scope {}{source}.", scope.as_str());
    match scope {
        Scope::User => eprintln!(
            "              MCP entry and SessionStart hook -> your home directory\n              instructions and skill          -> {}\n              Use --scope project to put the MCP entry and hook in the project.",
            project.display()
        ),
        Scope::Project => eprintln!(
            "              MCP entry, hook, instructions and skill -> {}\n              Note: a project-scoped MCP entry is not visible from a git worktree or a clone.",
            project.display()
        ),
    }
}

/// A user-scope run over a project-scope install left in place by the old
/// default.
///
/// Claude Code silently prefers the user entry, so the project one becomes
/// inert with nothing said about it. THREE RULES, all load-bearing:
///
///  1. It NEVER sets `failure` and never changes the exit code.
///     `inspect_owned_connection` returns `Err` when the project entry is
///     unmanaged or hand-edited; that becomes a warning string, not a refusal.
///     A diagnostic that can fail the command it diagnoses is removed by the
///     first person it annoys.
///  2. It NEVER removes anything. Implicit removal during `init` is exactly the
///     silent destructive act this change set exists to avoid; `teardown` is
///     the verb for removal, and the message names it.
///  3. It runs under `--dry-run` too, because a dry run is where a user checks
///     what a default change did to them.
fn project_scope_carryover(
    scope: Scope,
    hosts: &[Host],
    project: Option<&std::path::Path>,
) -> Vec<serde_json::Value> {
    if scope != Scope::User {
        return Vec::new();
    }
    let mut found = Vec::new();
    for host in hosts {
        let host = *host;
        let mut stale: Vec<String> = Vec::new();
        match kaleidoscope_manager::host::inspect_owned_connection(host, Scope::Project, project) {
            Ok(Some(_)) => {
                if let Ok(paths) = kaleidoscope_manager::host::canonical_paths(project) {
                    if let Some(path) = paths.get(&(host, Scope::Project)) {
                        stale.push(path.display().to_string());
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                found.push(serde_json::json!({
                    "step": "project_scope_carryover",
                    "host": host,
                    "status": "warning",
                    "detail": format!(
                        "a project-scope Kaleidoscope entry is present and the manager cannot read its ownership ({error}). It was NOT touched."
                    ),
                }));
                continue;
            }
        }
        if host == Host::ClaudeCode {
            if let Ok(settings) =
                kaleidoscope_manager::hooks::settings_path(Scope::Project, project)
            {
                if let Ok(plan) =
                    kaleidoscope_manager::hooks::plan_remove_at(Scope::Project, &settings, false)
                {
                    if !plan.is_noop() {
                        stale.push(settings.display().to_string());
                    }
                }
            }
        }
        if !stale.is_empty() {
            found.push(serde_json::json!({
                "step": "project_scope_carryover",
                "host": host,
                "status": "warning",
                "detail": format!(
                    "a project-scope install is still present at {}. The harness prefers the user entry, so the project one is now inert. Nothing was removed.",
                    stale.join(" and ")
                ),
                "remedy": format!(
                    "kaleidoscope teardown --host {} --scope project",
                    host.as_str()
                ),
            }));
        }
    }
    found
}

fn apply_step(step: Step, dry_run: bool, yes: bool) -> Result<serde_json::Value> {
    match step {
        Step::Skipped(reason) => Ok(serde_json::json!({
            "status": "skipped",
            "detail": reason,
        })),
        Step::Connection(plan) => {
            eprintln!("{}", plan.preview());
            if dry_run {
                return Ok(plan.summary(true));
            }
            if !plan.is_noop() && !yes {
                confirm()?;
            }
            plan.apply()?;
            Ok(plan.summary(false))
        }
        Step::Instruction(plan) => {
            eprintln!("{}", plan.preview());
            if dry_run {
                return Ok(plan.summary(true));
            }
            if !plan.is_noop() && !yes {
                confirm()?;
            }
            plan.apply()?;
            Ok(plan.summary(false))
        }
        Step::Hook(plan) => {
            eprintln!("{}", plan.preview());
            if dry_run {
                return Ok(plan.summary(true));
            }
            if !plan.is_noop() && !yes {
                confirm()?;
            }
            plan.apply()?;
            Ok(plan.summary(false))
        }
    }
}

/// Which instruction target a harness reads. Codex and `OpenCode` share
/// AGENTS.md, so `--host codex --host opencode` installs it ONCE: the receipt
/// is per-target, not per-host, and the second install reports `AlreadyInstalled`.
const fn instruction_target_for(host: Host) -> InstructionTarget {
    match host {
        Host::Codex | Host::OpenCode => InstructionTarget::Agents,
        Host::ClaudeCode => InstructionTarget::Claude,
        Host::Cursor => InstructionTarget::Cursor,
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn host_steps(
    manager: &Manager,
    host: Host,
    scope: Scope,
    profile: &str,
    descriptor: &kaleidoscope_manager::model::LaunchDescriptor,
    project: Option<&std::path::Path>,
    open_code_version: Option<OpenCodeVersion>,
    no_connect: bool,
    no_instructions: bool,
    no_skill: bool,
    no_hooks: bool,
) -> Result<Vec<(&'static str, Step)>> {
    let mut steps: Vec<(&'static str, Step)> = Vec::new();
    steps.push((
        "connect",
        if no_connect {
            // Required, not decorative. The two host-config refusals -- a
            // foreign `mcpServers.kaleidoscope` entry, and an unmanaged
            // `[mcp_servers.kaleidoscope]` TOML table -- must be able to name a
            // way forward, and before this flag existed there was none: the
            // user could keep their entry or abandon `init` entirely.
            Step::Skipped("--no-connect")
        } else {
            Step::Connection(Box::new(manager.plan_connect_using(
                host,
                scope,
                profile,
                descriptor,
                project,
                open_code_version,
            )?))
        },
    ));
    steps.push((
        "instructions",
        if no_instructions {
            Step::Skipped("--no-instructions")
        } else {
            Step::Instruction(Box::new(plan_instruction_install(
                instruction_target_for(host),
                None,
                project,
                false,
            )?))
        },
    ));
    steps.push((
        "skill",
        if no_skill {
            Step::Skipped("--no-skill")
        } else if host == Host::Cursor {
            // A refusal, not a silent skip -- but at the init level it is a
            // documented absence rather than an error, because the Cursor rule
            // IS the skill for Cursor and it was just installed above.
            Step::Skipped("cursor has no skill directory; its rule carries the instructions")
        } else {
            Step::Instruction(Box::new(plan_instruction_install(
                InstructionTarget::Skill,
                Some(host),
                project,
                false,
            )?))
        },
    ));
    steps.push((
        "hook",
        if no_hooks {
            Step::Skipped("--no-hooks")
        } else if host == Host::ClaudeCode {
            Step::Hook(Box::new(plan_hook_install(
                scope,
                &current_manager_path()?,
                profile,
                project,
            )?))
        } else {
            // See COMPATIBILITY.md's hook table: codex and cursor have no hook
            // mechanism (AGENTS.md and `alwaysApply: true` are the equivalents),
            // and OpenCode's plugin system is unverified here. Shipping an
            // unverified hook is the "unwired mitigation reads as an absent
            // hazard" defect and is worse than none, because the counter reads
            // zero and everyone concludes there is no problem.
            Step::Skipped("no verified hook mechanism for this harness; see COMPATIBILITY.md")
        },
    ));
    Ok(steps)
}

/// The absolute path of this executable, which is what goes into the hook's
/// `command`. A relative name would resolve against whatever cwd the harness
/// happens to have.
fn current_manager_path() -> Result<PathBuf> {
    env::current_exe().map_err(|error| ManagerError::io("resolve manager executable", error))
}

/// Reverses `init`, in reverse order: hook, skill, instructions, connection.
///
/// It NEVER touches the vault or the profile. Data removal is `profile remove`
/// plus `kscope vault-delete`, deliberately separate verbs, and this output
/// says so rather than leaving the user to assume either way.
#[allow(clippy::too_many_lines)]
fn run_teardown(
    manager: &Manager,
    engine: Option<&std::path::Path>,
    mut arguments: Vec<String>,
) -> Result<()> {
    let hosts = take_hosts(&mut arguments)?;
    let requested_scope = take_string_option(&mut arguments, "--scope")?;
    let scope_source = if requested_scope.is_some() {
        "flag"
    } else {
        "default"
    };
    // Must move with `init` or the two disagree about which file they mean.
    let scope = requested_scope.map_or(Ok(Scope::User), |value| Scope::from_str(&value))?;
    let explicit_project = take_path_option(&mut arguments, "--project")?;
    let force = take_flag(&mut arguments, "--force");
    let dry_run = take_flag(&mut arguments, "--dry-run");
    let yes = take_flag(&mut arguments, "--yes");
    require_empty(&arguments)?;
    if hosts.is_empty() {
        return Err(ManagerError::Usage(
            "teardown requires at least one --host".to_owned(),
        ));
    }
    let resolved_project = resolve_project_directory(engine, explicit_project.as_deref())?;
    let project = Some(resolved_project.directory.as_path());
    resolved_project.announce();
    announce_scope(scope, scope_source, &resolved_project.directory, true);
    // WHICH OTHER PROJECTS STILL DEPEND ON THE MACHINE-WIDE HALF.
    //
    // This is the measured harm the user-scope default introduced: `init` in
    // A, `init` in B, `teardown` in A -- and B listed ZERO MCP servers
    // afterwards while still carrying its Kaleidoscope CLAUDE.md, its
    // SKILL.md and both receipts. rc=0, `status: "removed"`, nothing on
    // stderr. Every symptom Defect 4 was raised to eliminate, reached through
    // the ordinary teardown path.
    //
    // The rule: the shared half goes when the LAST project goes. That needs no
    // new flag, cannot damage a project the command is not standing in, and
    // terminates -- each teardown removes one project, and the final one takes
    // the entry with it. `project_carries_instructions` is what makes it
    // self-healing: a registered project whose files are already gone stops
    // counting immediately.
    let store = ConfigStore::resolve().ok();
    let dependants: Vec<PathBuf> = store.as_ref().map_or_else(Vec::new, |store| {
        store.other_projects(&resolved_project.directory, |candidate| {
            kaleidoscope_manager::instructions::project_carries_instructions(candidate)
        })
    });
    let retain_shared = scope == Scope::User && !dependants.is_empty();

    let mut steps = Vec::new();
    let mut failure: Option<ManagerError> = None;
    let mut retained: Vec<&'static str> = Vec::new();
    let mut adopted_left: Vec<String> = Vec::new();
    // Set when an instruction or skill step found nothing to remove.
    //
    // `instructions.rs` has no `Scope`: CLAUDE.md, AGENTS.md, the Cursor rule
    // and SKILL.md are ALWAYS project-anchored. So a user who ran
    // `init --scope user` in project A and `teardown` from somewhere else gets
    // a clean-looking removal that left A's files behind -- reported as
    // `already_removed`, which is true of the directory the command was
    // standing in and useless to the person holding the orphan.
    //
    // The manager CANNOT fix this by searching: a user-scope install says
    // nothing about which projects the instructions went into, and there may be
    // fifty. What it can do is stop the report reading as "everything is gone"
    // when it means "nothing was here".
    let mut instructions_absent = false;
    for host in &hosts {
        let host = *host;
        let mut plans: Vec<(&'static str, Result<Step>)> = Vec::new();
        if host == Host::ClaudeCode && !retain_shared {
            plans.push((
                "hook",
                plan_hook_remove(scope, project, force).map(|plan| Step::Hook(Box::new(plan))),
            ));
        } else if host == Host::ClaudeCode {
            retained.push("hook");
            steps.push(serde_json::json!({
                "step": "hook",
                "host": host,
                "status": "retained",
                "scope": scope,
                "detail": "the user-scope SessionStart hook is machine-wide and other projects still carry Kaleidoscope instructions; it will be removed with the last of them",
            }));
        }
        if host != Host::Cursor {
            plans.push((
                "skill",
                plan_instruction_remove(InstructionTarget::Skill, Some(host), project, force)
                    .map(|plan| Step::Instruction(Box::new(plan))),
            ));
        }
        plans.push((
            "instructions",
            plan_instruction_remove(instruction_target_for(host), None, project, force)
                .map(|plan| Step::Instruction(Box::new(plan))),
        ));
        if retain_shared {
            retained.push("connect");
            steps.push(serde_json::json!({
                "step": "connect",
                "host": host,
                "status": "retained",
                "scope": scope,
                "detail": "the user-scope MCP entry is machine-wide and other projects still carry Kaleidoscope instructions; removing it here would leave them telling an agent to call tools that are no longer wired",
            }));
        } else {
            plans.push((
                "connect",
                manager
                    .plan_disconnect(host, scope, project)
                    .map(|plan| Step::Connection(Box::new(plan))),
            ));
        }
        for (name, planned) in plans {
            let outcome = planned.and_then(|step| {
                if let Step::Instruction(plan) = &step {
                    if plan.restore
                        == Some(kaleidoscope_manager::instructions::RestoreTier::AdoptedLeftInPlace)
                    {
                        adopted_left.push(plan.target().display().to_string());
                    }
                    if plan.is_noop() {
                        instructions_absent = true;
                    }
                }
                apply_step(step, dry_run, yes)
            });
            match outcome {
                Ok(mut value) => {
                    value["step"] = serde_json::json!(name);
                    value["host"] = serde_json::json!(host);
                    steps.push(value);
                }
                Err(error) => {
                    steps.push(serde_json::json!({
                        "step": name,
                        "host": host,
                        "status": "issue",
                        "detail": error.to_string(),
                    }));
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
    }
    let carryover = project_scope_carryover(scope, &hosts, project);
    steps.extend(carryover.iter().cloned());
    let mut next: Vec<String> = Vec::new();
    for host in &hosts {
        // An adopted ENTRY is removed, and it is reproducible on demand: by the
        // adoption test itself it is byte-identical to what `connect`
        // regenerates from the profile and the engine path.
        next.push(format!(
            "kaleidoscope connect {} --scope {}",
            host.as_str(),
            scope.as_str()
        ));
    }
    for step in &carryover {
        if let Some(remedy) = step.get("remedy").and_then(serde_json::Value::as_str) {
            next.push(remedy.to_owned());
        }
    }
    let mut note = "teardown removes host wiring only. To remove data, use `kaleidoscope profile remove NAME` and `kscope vault-delete ROOT`.".to_owned();
    for path in &adopted_left {
        let _ = write!(
            note,
            " {path} was adopted, not created, so it was left in place. Delete it by hand if you no longer want it."
        );
    }
    if instructions_absent {
        let _ = write!(
            note,
            " Instructions and the skill are ALWAYS project-anchored, whatever --scope says, and none was found at {}. This run did not remove them from anywhere else.",
            resolved_project.directory.display()
        );
        // NAME THE PROJECTS, now that there is a registry to name them from.
        //
        // The note used to end "if you installed them in a different project,
        // run this teardown from there" -- true, and useless to the person
        // holding the orphan, who is asking WHICH project. That was defended
        // as unfixable ("a user-scope install records nothing about which
        // projects the instructions went into"), which described the
        // implementation rather than a limit: `manager.json` is version 2 and
        // now records exactly that.
        if dependants.is_empty() {
            let _ = write!(
                note,
                " No other project is registered as carrying them either."
            );
        } else {
            let _ = write!(
                note,
                " These registered projects still do: {}. Run this teardown from each (or with --project PATH).",
                dependants
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if retain_shared {
        let _ = write!(
            note,
            " The machine-wide user-scope wiring ({}) was RETAINED: {} still carr{} manager-owned Kaleidoscope instructions, and removing the shared entry here would leave {} telling an agent to call `search` and `remember` with nothing behind them. It is removed automatically with the last of them; to remove it now, tear those down first (or pass --project PATH for each).",
            retained.join(" and "),
            dependants
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            if dependants.len() == 1 { "ies" } else { "y" },
            if dependants.len() == 1 { "it" } else { "them" },
        );
    }
    // DEREGISTER LAST, and only on a real run that got through cleanly. A
    // failed teardown leaves files behind, so forgetting the project would
    // lose the only record that they are there.
    if !dry_run && failure.is_none() {
        if let Some(store) = store.as_ref() {
            store.forget_project(&resolved_project.directory, |candidate| {
                kaleidoscope_manager::instructions::project_carries_instructions(candidate)
            });
        }
    }
    print_json(&serde_json::json!({
        "version": 1,
        "status": if dry_run { "dry_run" } else if failure.is_some() { "issues" } else if retain_shared { "partially_removed" } else { "removed" },
        "retained": retained,
        "dependent_projects": dependants,
        "scope": scope,
        "scope_source": scope_source,
        "scope_applies_to": ["connect", "hook"],
        "instructions_scope": "project",
        "project": resolved_project.report(),
        "steps": steps,
        "next": next,
        "vault": "untouched",
        "profile": "untouched",
        "note": note,
    }))?;
    failure.map_or(Ok(()), Err)
}

fn run_profile(manager: &Manager, mut arguments: Vec<String>) -> Result<()> {
    let action = arguments.first().cloned().ok_or_else(|| {
        ManagerError::Usage("profile requires list, show, use, or remove".to_owned())
    })?;
    arguments.remove(0);
    match action.as_str() {
        "list" => {
            require_empty(&arguments)?;
            print_json(&manager.profile_list()?)
        }
        "show" => {
            let name = one_argument(arguments, "profile show requires NAME")?;
            print_json(&manager.profile_show(&name)?)
        }
        "use" => {
            let name = one_argument(arguments, "profile use requires NAME")?;
            manager.profile_use(&name)?;
            print_json(&serde_json::json!({
                "version": 1,
                "status": "active",
                "profile": name,
            }))
        }
        "remove" => {
            let name = one_argument(arguments, "profile remove requires NAME")?;
            print_json(&manager.profile_remove(&name)?)
        }
        _ => Err(ManagerError::Usage(
            "profile requires list, show, use, or remove".to_owned(),
        )),
    }
}

/// Manages manager-local, non-secret profile-to-account references without
/// resolving the engine or contacting the account service.
fn run_profile_account(mut arguments: Vec<String>) -> Result<()> {
    let marker = arguments.first().ok_or_else(|| {
        ManagerError::Usage("profile account requires show, bind, or unbind".to_owned())
    })?;
    if marker != "account" {
        return Err(ManagerError::Usage(USAGE.to_owned()));
    }
    arguments.remove(0);
    let action = arguments.first().cloned().ok_or_else(|| {
        ManagerError::Usage("profile account requires show, bind, or unbind".to_owned())
    })?;
    arguments.remove(0);
    let store = ConfigStore::resolve()?;
    match action.as_str() {
        "show" => {
            let explicit =
                optional_profile_argument(arguments, "profile account show accepts [NAME]")?;
            let profile = store.selected_profile(explicit.as_deref())?;
            print_json(&serde_json::json!({
                "version": 1,
                "profile": profile,
                "account_id": store.profile_account_binding(&profile)?,
            }))
        }
        "bind" => {
            if !(1..=2).contains(&arguments.len()) {
                return Err(ManagerError::Usage(
                    "profile account bind requires ACCOUNT_UUID [NAME]".to_owned(),
                ));
            }
            let account_id = Uuid::parse_str(&arguments[0]).map_err(|_| {
                ManagerError::Usage("profile account bind requires a valid account UUID".to_owned())
            })?;
            let profile = store.selected_profile(arguments.get(1).map(String::as_str))?;
            store.bind_profile_account(&profile, account_id)?;
            print_json(&serde_json::json!({
                "version": 1,
                "status": "bound",
                "profile": profile,
                "account_id": account_id,
            }))
        }
        "unbind" => {
            let explicit =
                optional_profile_argument(arguments, "profile account unbind accepts [NAME]")?;
            let profile = store.selected_profile(explicit.as_deref())?;
            store.unbind_profile_account(&profile)?;
            print_json(&serde_json::json!({
                "version": 1,
                "status": "unbound",
                "profile": profile,
                "account_id": serde_json::Value::Null,
            }))
        }
        _ => Err(ManagerError::Usage(
            "profile account requires show, bind, or unbind".to_owned(),
        )),
    }
}

fn run_config(manager: &Manager, mut arguments: Vec<String>) -> Result<()> {
    let profile = take_string_option(&mut arguments, "--profile")?;
    let json = take_flag(&mut arguments, "--json");
    require_empty(&arguments)?;
    let (profile, descriptor) = manager.config_descriptor(profile.as_deref())?;
    if json {
        print_json(&descriptor)
    } else {
        println!("Profile: {profile}");
        println!("Transport: {}", descriptor.transport);
        println!("Command: {}", descriptor.command.display());
        println!("Arguments: {}", descriptor.args.join(" "));
        println!("Tools: {}", descriptor.tools.join(", "));
        Ok(())
    }
}

fn run_connection(
    manager: &Manager,
    engine: Option<&std::path::Path>,
    connect: bool,
    mut arguments: Vec<String>,
) -> Result<()> {
    if arguments.is_empty() {
        return Err(ManagerError::Usage(
            "connect/disconnect requires a host".to_owned(),
        ));
    }
    let host = Host::from_str(&arguments.remove(0))?;
    let requested_scope = take_string_option(&mut arguments, "--scope")?;
    let scope_source = if requested_scope.is_some() {
        "flag"
    } else {
        "default"
    };
    let scope = requested_scope.map_or(Ok(Scope::User), |value| Scope::from_str(&value))?;
    let profile = take_string_option(&mut arguments, "--profile")?;
    if !connect && profile.is_some() {
        return Err(ManagerError::Usage(
            "--profile is valid only for connect".to_owned(),
        ));
    }
    let explicit_project = take_path_option(&mut arguments, "--project")?;
    let open_code_version = take_string_option(&mut arguments, "--opencode-version")?
        .map_or(Ok(None), |value| {
            OpenCodeVersion::from_str(&value).map(Some)
        })?;
    if !connect && open_code_version.is_some() {
        return Err(ManagerError::Usage(
            "--opencode-version is valid only for connect".to_owned(),
        ));
    }
    let dry_run = take_flag(&mut arguments, "--dry-run");
    let yes = take_flag(&mut arguments, "--yes");
    require_empty(&arguments)?;
    let resolved_project = resolve_project_directory(engine, explicit_project.as_deref())?;
    let project = Some(resolved_project.directory.as_path());
    resolved_project.announce();
    let plan = if connect {
        manager.plan_connect(host, scope, profile.as_deref(), project, open_code_version)?
    } else {
        manager.plan_disconnect(host, scope, project)?
    };
    eprintln!("{}", plan.preview());
    if dry_run {
        let mut summary = plan.summary(true);
        summary["scope_source"] = serde_json::json!(scope_source);
        return print_json(&summary);
    }
    if !plan.is_noop() && !yes {
        confirm()?;
    }
    plan.apply()?;
    let mut summary = plan.summary(false);
    summary["scope_source"] = serde_json::json!(scope_source);
    print_json(&summary)
}

/// `doctor` is the ONE command with an exit code of its own.
///
/// It used to print `status: "issues"` and exit 0, so "the report says there
/// are issues" and "the command ran fine" were the same observation to any
/// caller that checked `$?`. `--json` is accepted and IGNORED -- the output is
/// always JSON -- because `run_init` prints `kaleidoscope doctor --json` in its
/// own `next` array, and that exact command was rejected with a usage error.
fn run_doctor(
    manager: &Manager,
    engine: Option<&std::path::Path>,
    mut arguments: Vec<String>,
) -> Result<()> {
    let explicit_project = take_path_option(&mut arguments, "--project")?;
    let _json = take_flag(&mut arguments, "--json");
    require_empty(&arguments)?;
    // DOCTOR DOES NOT DIE ON THE THING IT EXISTS TO DIAGNOSE.
    //
    // `resolve_project_directory` refuses when the engine cannot answer -- the
    // right call for `init` and `teardown`, where guessing a directory means
    // writing files into the wrong tree. For `doctor` it was catastrophic in
    // exactly the case a user needs it most: against an engine without
    // `where --root-only`, `doctor --json` exited 2 and printed NOTHING on
    // stdout, so the command whose job is to say what is wrong was the command
    // that could not run. It now records the failure AS A CHECK, falls back to
    // the working directory for the project-anchored checks, and still prints
    // a report -- at rc=3, which is "there are issues", not rc=2, which is
    // "this could not run".
    let (resolved_project, project_problem) =
        match resolve_project_directory(engine, explicit_project.as_deref()) {
            Ok(resolved) => (resolved, None),
            Err(error) => {
                let fallback = kaleidoscope_manager::config::project_root(None)?;
                (
                    ProjectDirectory {
                        directory: fallback,
                        source: "unresolved_fallback".to_owned(),
                        marker: None,
                        repository: None,
                        differs_from_cwd: false,
                    },
                    Some(error.to_string()),
                )
            }
        };
    let mut report = manager.doctor(Some(&resolved_project.directory));
    if let Some(problem) = project_problem {
        report.checks.insert(
            0,
            kaleidoscope_manager::doctor::DoctorCheck {
                name: "project.root".to_owned(),
                status: "issue",
                detail: format!(
                    "{problem} The project-anchored checks below were run against the working directory instead, so they may be describing the wrong tree."
                ),
                managed: None,
            },
        );
        report.status = "issues";
    }
    let issues = report
        .checks
        .iter()
        .filter(|check| check.status == "issue")
        .count();
    let mut value = serde_json::to_value(&report)
        .map_err(|_| ManagerError::InvalidManagerConfig("cannot encode output"))?;
    value["project"] = resolved_project.report();
    print_json(&value)?;
    if issues > 0 {
        return Err(ManagerError::DoctorIssues(issues));
    }
    Ok(())
}

fn confirm() -> Result<()> {
    eprint!("Apply this change? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| ManagerError::io("flush confirmation", error))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| ManagerError::io("read confirmation", error))?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(ManagerError::Cancelled)
    }
}

fn take_flag(arguments: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = arguments.iter().position(|argument| argument == flag) {
        arguments.remove(index);
        true
    } else {
        false
    }
}

fn take_string_option(arguments: &mut Vec<String>, option: &str) -> Result<Option<String>> {
    let Some(index) = arguments.iter().position(|argument| argument == option) else {
        return Ok(None);
    };
    arguments.remove(index);
    if index >= arguments.len() {
        return Err(ManagerError::Usage(format!("{option} requires a value")));
    }
    Ok(Some(arguments.remove(index)))
}

fn take_path_option(arguments: &mut Vec<String>, option: &str) -> Result<Option<PathBuf>> {
    take_string_option(arguments, option).map(|value| value.map(PathBuf::from))
}

fn require_empty(arguments: &[String]) -> Result<()> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(ManagerError::Usage(format!(
            "unexpected arguments: {}",
            arguments.join(" ")
        )))
    }
}

fn one_argument(arguments: Vec<String>, message: &str) -> Result<String> {
    // Two different mistakes, two different messages. Both arms used to print
    // "<verb> requires NAME", so `profile remove journey --yes` -- where the
    // NAME was supplied and `--yes` is simply not accepted here -- blamed the
    // one argument the user got right.
    match arguments.len() {
        1 => Ok(arguments.into_iter().next().expect("one argument")),
        0 => Err(ManagerError::Usage(message.to_owned())),
        _ => Err(ManagerError::Usage(format!(
            "{message} and takes nothing else; unexpected: {}",
            arguments[1..].join(" ")
        ))),
    }
}

fn optional_profile_argument(arguments: Vec<String>, message: &str) -> Result<Option<String>> {
    match arguments.len() {
        0 => Ok(None),
        1 => Ok(arguments.into_iter().next()),
        _ => Err(ManagerError::Usage(message.to_owned())),
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(value)
            .map_err(|_| ManagerError::InvalidManagerConfig("cannot encode output"))?
    );
    Ok(())
}

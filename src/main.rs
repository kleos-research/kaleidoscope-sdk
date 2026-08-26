use std::env;
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
    plan_install as plan_hook_install, plan_remove as plan_hook_remove, session_start_output,
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
                                      [--no-instructions] [--no-skill] [--no-hooks]
                                      [--adopt | --create] [--dry-run] [--yes]
  kaleidoscope [--engine PATH] teardown [--host HOST]... [--scope user|project]
                                      [--project PATH] [--force] [--dry-run] [--yes]
  kaleidoscope [--engine PATH] hook session-start --profile NAME
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
  kaleidoscope [--engine PATH] doctor [--project PATH]
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
Project scope is the default. Use --dry-run for an effect-free plan.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
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
        return run_instructions(arguments);
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
        "init" => run_init(&manager, arguments),
        "profile" => run_profile(&manager, arguments),
        "config" => run_config(&manager, arguments),
        "connect" => run_connection(&manager, true, arguments),
        "disconnect" => run_connection(&manager, false, arguments),
        "teardown" => run_teardown(&manager, arguments),
        "doctor" => run_doctor(&manager, arguments),
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

fn run_instructions(mut arguments: Vec<String>) -> Result<()> {
    if arguments.len() < 2 {
        return Err(ManagerError::Usage(
            "instructions requires install|remove and skill|agents|claude|cursor".to_owned(),
        ));
    }
    let action = arguments.remove(0);
    let target = InstructionTarget::from_str(&arguments.remove(0))?;
    let host = take_string_option(&mut arguments, "--host")?
        .map_or(Ok(None), |value| Host::from_str(&value).map(Some))?;
    let project = take_path_option(&mut arguments, "--project")?;
    let force = take_flag(&mut arguments, "--force");
    let dry_run = take_flag(&mut arguments, "--dry-run");
    let yes = take_flag(&mut arguments, "--yes");
    require_empty(&arguments)?;
    let plan = match action.as_str() {
        "install" => plan_instruction_install(target, host, project.as_deref(), force)?,
        "remove" | "uninstall" => plan_instruction_remove(target, host, project.as_deref(), force)?,
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

/// The hook body. Invoked BY the harness, not by users. Exits 0 always -- a
/// hook that exits non-zero is a hook the user turns off, and a broken memory
/// configuration should be visible in the session rather than fatal to it.
fn run_hook(engine: Option<&std::path::Path>, mut arguments: Vec<String>) -> Result<()> {
    let action = arguments
        .first()
        .cloned()
        .ok_or_else(|| ManagerError::Usage("hook requires session-start".to_owned()))?;
    if action != "session-start" {
        return Err(ManagerError::Usage("hook requires session-start".to_owned()));
    }
    arguments.remove(0);
    let profile =
        take_string_option(&mut arguments, "--profile")?.unwrap_or_else(|| "default".to_owned());
    require_empty(&arguments)?;
    // `Manager::resolve` also opens the config store; the hook only needs the
    // engine, and it must not fail if the config store is unreadable.
    // The Result is KEPT, not `.ok()`-ed: `session_start_output` interpolates
    // the reason, and discarding it here is what made an engine that was found
    // and rejected read as an engine that was not installed.
    let resolved = kaleidoscope_manager::engine::Engine::resolve(engine);
    println!("{}", session_start_output(resolved.as_ref(), &profile));
    Ok(())
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
fn run_init(manager: &Manager, mut arguments: Vec<String>) -> Result<()> {
    let root = take_path_option(&mut arguments, "--root")?;
    let profile =
        take_string_option(&mut arguments, "--profile")?.unwrap_or_else(|| "default".to_owned());
    let durability = take_string_option(&mut arguments, "--durability")?
        .map_or(Ok(Durability::ProcessLocal), |value| {
            Durability::from_str(&value)
        })?;
    let hosts = take_hosts(&mut arguments)?;
    let scope = take_string_option(&mut arguments, "--scope")?
        .map_or(Ok(Scope::Project), |value| Scope::from_str(&value))?;
    let project = take_path_option(&mut arguments, "--project")?;
    let open_code_version = take_string_option(&mut arguments, "--opencode-version")?
        .map_or(Ok(None), |value| {
            OpenCodeVersion::from_str(&value).map(Some)
        })?;
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

    let initialized = manager.init(&profile, root.as_deref(), durability, policy, project.as_deref())?;
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
    for host in &hosts {
        if failure.is_some() {
            break;
        }
        let host = *host;
        let plans = host_steps(
            manager,
            host,
            scope,
            &profile,
            project.as_deref(),
            open_code_version,
            no_instructions,
            no_skill,
            no_hooks,
        );
        match plans {
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
    print_json(&serde_json::json!({
        "version": 1,
        "status": if dry_run { "dry_run" } else { initialized.status },
        "profile": profile_summary(&initialized.profile),
        "vault": {
            "discovered_by": initialized.discovered_by,
            "discovered_detail": initialized.discovered_detail,
            "workspaces": initialized.workspaces,
            "created": initialized.created,
        },
        "launch": initialized.launch,
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

/// Which instruction target a harness reads. Codex and OpenCode share
/// AGENTS.md, so `--host codex --host opencode` installs it ONCE: the receipt
/// is per-target, not per-host, and the second install reports AlreadyInstalled.
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
    project: Option<&std::path::Path>,
    open_code_version: Option<OpenCodeVersion>,
    no_instructions: bool,
    no_skill: bool,
    no_hooks: bool,
) -> Result<Vec<(&'static str, Step)>> {
    let mut steps: Vec<(&'static str, Step)> = Vec::new();
    steps.push((
        "connect",
        Step::Connection(Box::new(manager.plan_connect(
            host,
            scope,
            Some(profile),
            project,
            open_code_version,
        )?)),
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
fn run_teardown(manager: &Manager, mut arguments: Vec<String>) -> Result<()> {
    let hosts = take_hosts(&mut arguments)?;
    let scope = take_string_option(&mut arguments, "--scope")?
        .map_or(Ok(Scope::Project), |value| Scope::from_str(&value))?;
    let project = take_path_option(&mut arguments, "--project")?;
    let force = take_flag(&mut arguments, "--force");
    let dry_run = take_flag(&mut arguments, "--dry-run");
    let yes = take_flag(&mut arguments, "--yes");
    require_empty(&arguments)?;
    if hosts.is_empty() {
        return Err(ManagerError::Usage(
            "teardown requires at least one --host".to_owned(),
        ));
    }
    let mut steps = Vec::new();
    let mut failure: Option<ManagerError> = None;
    for host in &hosts {
        let host = *host;
        let mut plans: Vec<(&'static str, Result<Step>)> = Vec::new();
        if host == Host::ClaudeCode {
            plans.push((
                "hook",
                plan_hook_remove(scope, project.as_deref(), force)
                    .map(|plan| Step::Hook(Box::new(plan))),
            ));
        }
        if host != Host::Cursor {
            plans.push((
                "skill",
                plan_instruction_remove(
                    InstructionTarget::Skill,
                    Some(host),
                    project.as_deref(),
                    force,
                )
                .map(|plan| Step::Instruction(Box::new(plan))),
            ));
        }
        plans.push((
            "instructions",
            plan_instruction_remove(
                instruction_target_for(host),
                None,
                project.as_deref(),
                force,
            )
            .map(|plan| Step::Instruction(Box::new(plan))),
        ));
        plans.push((
            "connect",
            manager
                .plan_disconnect(host, scope, project.as_deref())
                .map(|plan| Step::Connection(Box::new(plan))),
        ));
        for (name, planned) in plans {
            let outcome = planned.and_then(|step| apply_step(step, dry_run, yes));
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
    print_json(&serde_json::json!({
        "version": 1,
        "status": if dry_run { "dry_run" } else if failure.is_some() { "issues" } else { "removed" },
        "steps": steps,
        "vault": "untouched",
        "profile": "untouched",
        "note": "teardown removes host wiring only. To remove data, use `kaleidoscope profile remove NAME` and `kscope vault-delete ROOT`.",
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

fn run_connection(manager: &Manager, connect: bool, mut arguments: Vec<String>) -> Result<()> {
    if arguments.is_empty() {
        return Err(ManagerError::Usage(
            "connect/disconnect requires a host".to_owned(),
        ));
    }
    let host = Host::from_str(&arguments.remove(0))?;
    let scope = take_string_option(&mut arguments, "--scope")?
        .map_or(Ok(Scope::Project), |value| Scope::from_str(&value))?;
    let profile = take_string_option(&mut arguments, "--profile")?;
    if !connect && profile.is_some() {
        return Err(ManagerError::Usage(
            "--profile is valid only for connect".to_owned(),
        ));
    }
    let project = take_path_option(&mut arguments, "--project")?;
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
    let plan = if connect {
        manager.plan_connect(
            host,
            scope,
            profile.as_deref(),
            project.as_deref(),
            open_code_version,
        )?
    } else {
        manager.plan_disconnect(host, scope, project.as_deref())?
    };
    eprintln!("{}", plan.preview());
    if dry_run {
        return print_json(&plan.summary(true));
    }
    if !plan.is_noop() && !yes {
        confirm()?;
    }
    plan.apply()?;
    print_json(&plan.summary(false))
}

fn run_doctor(manager: &Manager, mut arguments: Vec<String>) -> Result<()> {
    let project = take_path_option(&mut arguments, "--project")?;
    require_empty(&arguments)?;
    print_json(&manager.doctor(project.as_deref()))
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

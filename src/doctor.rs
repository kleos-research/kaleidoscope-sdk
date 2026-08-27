use std::path::Path;

use serde::Serialize;

use crate::config::ConfigStore;
use crate::engine::Engine;
use crate::hooks::{plan_remove_at as plan_hook_remove_at, settings_path};
use crate::host::{Host, Scope, inspect_owned_connection};
use crate::instructions::{InstructionTarget, plan_remove, plan_remove_at};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: &'static str,
    pub detail: String,
    /// Whether the thing this check names is under manager ownership.
    ///
    /// `None` for checks that are not about ownership (engine, profiles).
    /// `Some(false)` is the state that used to be indistinguishable from
    /// `Some(true)` in the report: BOTH printed `status: "ok"`, one saying
    /// "manager-owned entry and owner receipt match" and the other "not
    /// managed", so a machine reading `status` could not tell a clean host from
    /// a half-installed one -- and neither could the `status: "ready"` verdict
    /// computed from those statuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorReport {
    pub version: u32,
    pub status: &'static str,
    pub offline: bool,
    pub redacted: bool,
    pub checks: Vec<DoctorCheck>,
}

#[must_use]
pub fn run_doctor(engine: &Engine, config: &ConfigStore, project: Option<&Path>) -> DoctorReport {
    let mut checks = Vec::new();
    push_result(
        &mut checks,
        "engine.version",
        engine.version().map(|version| format!("kscope {version}")),
    );
    push_result(
        &mut checks,
        "engine.public_contract",
        engine
            .public_contract_seed()
            .map(|_| "offline local stdio boundary accepted".to_owned()),
    );
    let profiles = engine.profile_list();
    push_result(
        &mut checks,
        "profiles",
        profiles
            .as_ref()
            .map(|list| format!("{} native profile(s) validated", list.profiles.len()))
            .map_err(std::string::ToString::to_string),
    );
    let active = config.load();
    match active {
        Ok(active) => {
            let selected = active
                .active_profile
                .unwrap_or_else(|| "default".to_owned());
            push_result(
                &mut checks,
                "profile.launch",
                engine
                    .profile_launch(&selected)
                    .map(|_| "active launch descriptor v1 validated".to_owned()),
            );
        }
        Err(error) => checks.push(DoctorCheck {
            name: "profile.launch".to_owned(),
            status: "issue",
            detail: generic_detail(&error.to_string()),
            managed: None,
        }),
    }
    for host in Host::ALL {
        for scope in [Scope::User, Scope::Project] {
            let name = format!("connection.{}.{}", host.as_str(), scope.as_str());
            match inspect_owned_connection(host, scope, project) {
                Ok(Some(_)) => checks.push(DoctorCheck {
                    name,
                    status: "ok",
                    detail: "manager-owned entry and owner receipt match".to_owned(),
                    managed: Some(true),
                }),
                Ok(None) => checks.push(DoctorCheck {
                    name,
                    status: "ok",
                    detail: "not managed".to_owned(),
                    managed: Some(false),
                }),
                Err(error) => checks.push(DoctorCheck {
                    name,
                    status: "issue",
                    detail: generic_detail(&error.to_string()),
                    managed: None,
                }),
            }
        }
    }
    push_instruction_checks(&mut checks, project);
    push_skill_checks(&mut checks, project);
    push_hook_checks(&mut checks, project);
    push_coherence_checks(&mut checks);
    let status = if checks.iter().any(|check| check.status == "issue") {
        "issues"
    } else {
        "ready"
    };
    DoctorReport {
        version: 1,
        status,
        offline: true,
        redacted: true,
        checks,
    }
}

fn push_result<E: ToString>(
    checks: &mut Vec<DoctorCheck>,
    name: &str,
    result: std::result::Result<String, E>,
) {
    match result {
        Ok(detail) => checks.push(DoctorCheck {
            name: name.to_owned(),
            status: "ok",
            detail,
            managed: None,
        }),
        Err(error) => checks.push(DoctorCheck {
            name: name.to_owned(),
            status: "issue",
            detail: generic_detail(&error.to_string()),
            managed: None,
        }),
    }
}

fn generic_detail(error: &str) -> String {
    if error.contains("owner receipt") || error.contains("configuration conflict") {
        "managed configuration ownership check failed".to_owned()
    } else if error.contains("profile") {
        "native profile validation failed".to_owned()
    } else if error.contains("engine") || error.contains("kscope") {
        "native engine validation failed".to_owned()
    } else {
        "local validation failed".to_owned()
    }
}

/// `doctor` used to run twelve checks -- engine, profiles, launch, and
/// connection.<host>.<scope> x 8 -- and ZERO about instructions, skills or
/// hooks. It was blind to three of the four things init is asked to do, so it
/// could report `ready` while the skill sat in a directory no harness reads.
/// A displayed metric that gates nothing is not a check.
///
/// Every one of these reuses the same receipt-versus-file comparison the
/// removal plans use, so a check cannot report `ok` for a state a removal would
/// refuse. None opens a vault or contacts anything: `offline: true` and
/// `redacted: true` stay true.
fn push_instruction_checks(checks: &mut Vec<DoctorCheck>, project: Option<&Path>) {
    for target in [
        InstructionTarget::Agents,
        InstructionTarget::Claude,
        InstructionTarget::Cursor,
    ] {
        let name = format!("instructions.{}", target.as_str());
        push_managed(
            checks,
            name,
            plan_remove(target, None, project, false).map(|plan| {
                if plan.is_noop() {
                    "not managed".to_owned()
                } else {
                    format!(
                        "manager-owned block and receipt match at {}",
                        plan.target.display()
                    )
                }
            }),
        );
    }
}

fn push_skill_checks(checks: &mut Vec<DoctorCheck>, project: Option<&Path>) {
    // Cursor is deliberately absent: it has no skill directory, and its rule is
    // covered by `instructions.cursor`.
    for host in [Host::ClaudeCode, Host::Codex, Host::OpenCode] {
        let name = format!("skill.{}", host.as_str());
        let root = match crate::config::project_root(project) {
            Ok(root) => root,
            Err(error) => {
                checks.push(DoctorCheck {
                    name,
                    status: "issue",
                    detail: generic_detail(&error.to_string()),
                    managed: None,
                });
                continue;
            }
        };
        push_managed(
            checks,
            name,
            plan_remove_at(InstructionTarget::Skill, Some(host), &root, false).map(|plan| {
                if plan.is_noop() {
                    "not managed".to_owned()
                } else {
                    format!("installed and byte-identical at {}", plan.target.display())
                }
            }),
        );
    }
}

fn push_hook_checks(checks: &mut Vec<DoctorCheck>, project: Option<&Path>) {
    for scope in [Scope::User, Scope::Project] {
        let name = format!("hook.claude-code.{}", scope.as_str());
        let target = match settings_path(scope, project) {
            Ok(path) => path,
            Err(error) => {
                checks.push(DoctorCheck {
                    name,
                    status: "issue",
                    detail: generic_detail(&error.to_string()),
                    managed: None,
                });
                continue;
            }
        };
        push_managed(
            checks,
            name,
            plan_hook_remove_at(scope, &target, false).map(|plan| {
                if plan.is_noop() {
                    "not managed".to_owned()
                } else {
                    format!(
                        "SessionStart entry and receipt match at {}",
                        plan.target.display()
                    )
                }
            }),
        );
    }
}

fn push_managed<E: ToString>(
    checks: &mut Vec<DoctorCheck>,
    name: String,
    result: std::result::Result<String, E>,
) {
    match result {
        Ok(detail) => {
            let managed = detail != "not managed";
            checks.push(DoctorCheck {
                name,
                status: "ok",
                detail,
                managed: Some(managed),
            });
        }
        Err(error) => checks.push(DoctorCheck {
            name,
            status: "issue",
            detail: generic_detail(&error.to_string()),
            managed: None,
        }),
    }
}

/// Is this named check reporting manager ownership?
fn is_managed(checks: &[DoctorCheck], name: &str) -> bool {
    checks
        .iter()
        .any(|check| check.name == name && check.managed == Some(true))
}

/// THE CHECK THAT CATCHES A HALF-INSTALLED PROJECT.
///
/// Every individual check can be `ok` while the configuration as a whole is
/// broken, and that is not hypothetical: under user scope the host entry and
/// the hook are MACHINE-WIDE while the instructions and the skill are
/// project-anchored, so tearing down in one project removed the shared entry
/// and left every other project carrying a `CLAUDE.md` that tells the agent to
/// call `search` and `remember` with nothing behind them. `doctor` graded that
/// project `ready`, rc=0, every check `ok` -- because "not managed" was `ok`
/// and no check compared one to another.
///
/// The predicate is deliberately one-directional. Instructions without a
/// connection is a broken state; a connection without instructions is what
/// `--no-instructions` is FOR, and flagging it would make the documented flag
/// produce a permanent issue.
fn push_coherence_checks(checks: &mut Vec<DoctorCheck>) {
    for host in Host::ALL {
        let instructions = format!("instructions.{}", instruction_target_for(host).as_str());
        let skill = format!("skill.{}", host.as_str());
        let told = is_managed(checks, &instructions)
            || (host != Host::Cursor && is_managed(checks, &skill));
        if !told {
            continue;
        }
        let wired = is_managed(checks, &format!("connection.{}.user", host.as_str()))
            || is_managed(checks, &format!("connection.{}.project", host.as_str()));
        let name = format!("wiring.{}", host.as_str());
        if wired {
            checks.push(DoctorCheck {
                name,
                status: "ok",
                detail: "instructions and a manager-owned MCP entry are both present".to_owned(),
                managed: Some(true),
            });
        } else {
            checks.push(DoctorCheck {
                name,
                status: "issue",
                detail: format!(
                    "this project carries manager-owned Kaleidoscope instructions but NO manager-owned MCP entry in either scope, so the agent is told to call `search` and `remember` and has nothing to call. Run `kaleidoscope connect {host}` to wire it, or `kaleidoscope teardown --host {host}` to remove the instructions too.",
                    host = host.as_str()
                ),
                managed: Some(false),
            });
        }
    }
}

/// Which instruction target a harness reads. Mirrors `main.rs`; kept `const`
/// and total so a new host cannot be added without deciding this.
const fn instruction_target_for(host: Host) -> InstructionTarget {
    match host {
        Host::Codex | Host::OpenCode => InstructionTarget::Agents,
        Host::ClaudeCode => InstructionTarget::Claude,
        Host::Cursor => InstructionTarget::Cursor,
    }
}

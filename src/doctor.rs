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
                }),
                Ok(None) => checks.push(DoctorCheck {
                    name,
                    status: "ok",
                    detail: "not managed".to_owned(),
                }),
                Err(error) => checks.push(DoctorCheck {
                    name,
                    status: "issue",
                    detail: generic_detail(&error.to_string()),
                }),
            }
        }
    }
    push_instruction_checks(&mut checks, project);
    push_skill_checks(&mut checks, project);
    push_hook_checks(&mut checks, project);
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
        }),
        Err(error) => checks.push(DoctorCheck {
            name: name.to_owned(),
            status: "issue",
            detail: generic_detail(&error.to_string()),
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
        push_managed(checks, name, plan_remove(target, None, project, false).map(|plan| {
            if plan.is_noop() {
                "not managed".to_owned()
            } else {
                format!("manager-owned block and receipt match at {}", plan.target.display())
            }
        }));
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
                    format!("SessionStart entry and receipt match at {}", plan.target.display())
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
        Ok(detail) => checks.push(DoctorCheck {
            name,
            status: "ok",
            detail,
        }),
        Err(error) => checks.push(DoctorCheck {
            name,
            status: "issue",
            detail: generic_detail(&error.to_string()),
        }),
    }
}

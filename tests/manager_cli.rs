#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const CANARIES: &[(&str, &str)] = &[
    ("OPENAI_API_KEY", "openai-token-canary"),
    ("ANTHROPIC_API_KEY", "anthropic-token-canary"),
    ("AWS_SECRET_ACCESS_KEY", "aws-key-canary"),
    ("KSCOPE_ROOT", "vault-root-secret"),
    ("KSCOPE_WORKSPACE", "wsp_secret"),
    ("KSCOPE_PRINCIPAL", "usr_secret"),
    ("KSCOPE_JOURNAL", "journal:secret"),
    ("KALEIDOSCOPE_TOKEN", "manager-token-secret"),
    ("UNRELATED_SECRET_TOKEN", "unrelated-token-canary"),
];

struct Fixture {
    temp: TempDir,
    engine: PathBuf,
    log: PathBuf,
    home: PathBuf,
    project: PathBuf,
    config_home: PathBuf,
    profile_home: PathBuf,
    data_home: PathBuf,
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new(invalid_descriptor: bool) -> Self {
        let temp = TempDir::new().unwrap();
        let canonical_temp = fs::canonicalize(temp.path()).unwrap();
        let engine = canonical_temp.join("fake engine 🪞");
        let log = canonical_temp.join("engine-environment.log");
        let home = canonical_temp.join("home");
        let project = canonical_temp.join("project with spaces ü");
        let config_home = canonical_temp.join("manager-config");
        let profile_home = canonical_temp.join("native-profiles");
        let data_home = canonical_temp.join("manager-data");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&config_home).unwrap();
        let engine_json = serde_json::to_string(engine.to_str().unwrap()).unwrap();
        let environment = if invalid_descriptor {
            r#"{"provider_token":"token-secret"}"#
        } else {
            "{}"
        };
        // The fake engine keeps a real profile registry on disk and creates a
        // real vault directory, because the manager now DISCOVERS before it
        // decides. A fixture whose `profile show` always succeeds cannot
        // distinguish "adopt the existing profile" from "create a new one",
        // and a fixture that never writes a manifest cannot exercise the
        // fork guard at all.
        let script = format!(
            r#"#!/bin/sh
LOG={log}
REG="$KSCOPE_PROFILE_HOME"
mkdir -p "$REG" 2>/dev/null
{{
  printf 'ARGS'
  for value in "$@"; do printf ' <%s>' "$value"; done
  printf '\n'
  /usr/bin/env
  printf '%s\n' '---'
}} >> "$LOG"
launch() {{
  printf '%s\n' '{{"version":1,"transport":"stdio","command":{engine},"args":["mcp","--profile","'"$1"'"],"tools":["search","remember"],"environment":{environment}}}'
}}
emit_profile() {{
  printf '%s\n' '{{"version":1,"name":"'"$1"'","root":"'"$2"'","workspace_id":"wsp_secret","principal_id":"usr_secret","journal":"journal:secret","durability":"'"$3"'"}}'
}}
make_vault() {{
  mkdir -p "$1/workspaces/wsp_secret" || exit 3
  printf '%s\n' '{{"schema_name":"filesystem.root-manifest","schema_version":1}}' > "$1/manifest.json"
}}
is_vault() {{
  test -f "$1/manifest.json" && grep -q 'filesystem.root-manifest' "$1/manifest.json"
}}
count_workspaces() {{
  ls -1 "$1/workspaces" 2>/dev/null | grep -c '^wsp_'
}}
case "$1" in
  --version)
    printf '%s\n' 'kscope 0.1.0-test'
    ;;
  public-contract)
    printf '%s\n' '{{"schema_version":"kaleidoscope.public-seed.v1","capabilities":{{"network_required":false,"local_vault":true,"stdio_mcp":true,"operator_commands_in_mcp":false}}}}'
    ;;
  where)
    # `where --root-only` is the contract the manager asks for the project
    # root. It answers with the WORKING DIRECTORY, which is what the manager
    # used to assume unconditionally -- so every test whose subject is
    # something else keeps its old expectations, and the tests whose subject
    # IS the walk drive it through the real engine instead.
    #
    # `--root-only` and nothing else: `where` on its own still resolves a full
    # vault address, and the manager must not be able to reach that path.
    if [ "$2" = "--root-only" ]; then
      here=$(pwd)
      printf '%s\n' '{{"root":"'"$here"'/.kaleidoscope","source":"working_directory_default","repository":null,"project":"'"$here"'","project_source":"working_directory_default","project_marker":null}}'
    else
      printf '%s\n' 'where requires a vault' >&2
      exit 2
    fi
    ;;
  init-profile)
    # The real engine does NOT refuse here: it happily adds a second
    # workspace. The fixture reproduces exactly that, so the manager's guard
    # is the only thing standing between `init` and a forked vault.
    if is_vault "$3"; then
      mkdir -p "$3/workspaces/wsp_forked_$$"
    else
      make_vault "$3"
    fi
    printf '%s\n' "$3" > "$REG/$2"
    printf '%s\n' "$5" >> "$REG/$2"
    printf '%s\n' '{{"version":1,"status":"initialized","profile":{{"version":1,"name":"'"$2"'","root":"'"$3"'","workspace_id":"wsp_secret","principal_id":"usr_secret","journal":"journal:secret","durability":"'"$5"'"}},"launch":{{"version":1,"transport":"stdio","command":{engine},"args":["mcp","--profile","'"$2"'"],"tools":["search","remember"],"environment":{environment}}}}}'
    ;;
  profile)
    case "$2" in
      list)
        names=$(ls -1 "$REG" 2>/dev/null | sort | sed 's/^/"/;s/$/"/' | paste -sd, -)
        printf '%s\n' '{{"version":1,"profiles":['"$names"']}}'
        ;;
      show)
        if [ ! -f "$REG/$3" ]; then
          printf '%s\n' 'profile is not registered' >&2
          exit 2
        fi
        emit_profile "$3" "$(sed -n 1p "$REG/$3")" "$(sed -n 2p "$REG/$3")"
        ;;
      import)
        # profile import NAME ROOT DURABILITY -> $3 NAME, $4 ROOT, $5 DURABILITY
        if ! is_vault "$4"; then
          printf '%s\n' 'profile root is not a Kaleidoscope vault' >&2
          exit 2
        fi
        count=$(count_workspaces "$4")
        if [ "$count" -gt 1 ]; then
          printf '%s\n' "vault has $count workspaces; select an explicit workspace instead of importing" >&2
          exit 2
        fi
        printf '%s\n' "$4" > "$REG/$3"
        printf '%s\n' "$5" >> "$REG/$3"
        emit_profile "$3" "$4" "$5"
        ;;
      launch)
        if [ ! -f "$REG/$3" ]; then
          printf '%s\n' 'profile is not registered' >&2
          exit 2
        fi
        launch "$3"
        ;;
      remove)
        rm -f "$REG/$3"
        printf '%s\n' '{{"version":1,"name":"'"$3"'","status":"removed"}}'
        ;;
      *) exit 64 ;;
    esac
    ;;
  *) exit 64 ;;
esac
"#,
            log = shell_quote(log.to_str().unwrap()),
            engine = engine_json,
            environment = environment,
        );
        fs::write(&engine, script).unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        // WARM THE FIRST EXECUTION, before any test times anything.
        //
        // The FIRST exec of a freshly written executable on macOS goes through
        // a serialized system policy assessment: measured at ~620 ms on an idle
        // machine, and far worse with a dozen fixtures doing it at once. Every
        // subsequent exec of the same file is ~6 ms.
        //
        // That cost is invisible to a test that only checks output, and it was
        // invisible here until the `SessionStart` hook grew a timeout -- at
        // which point the suite began reporting `profile_launch: "timed out
        // after 3001 ms"` for an engine that answers in six milliseconds, under
        // parallel load only. The measurement being made is the manager's
        // behaviour, not macOS's code-signing throughput, so the cost is paid
        // here, once, outside anybody's budget.
        //
        // The warm-up's own log entry is DELETED again immediately. Several
        // tests walk every entry in this log and assert that each carries
        // `KSCOPE_PROFILE_HOME` and none carries a canary, so a warm-up entry
        // written with any environment at all -- inherited or cleared -- fails
        // one of those two. Removing the file restores exactly the state before
        // the warm-up, which is "no log yet".
        let _ = Command::new(&engine).arg("--version").output();
        let _ = fs::remove_file(&log);
        Self {
            temp,
            engine,
            log,
            home,
            project,
            config_home,
            profile_home,
            data_home,
        }
    }

    fn command(&self, arguments: &[&str]) -> Output {
        self.command_with(&[], arguments)
    }

    /// The same invocation with EXTRA environment variables.
    ///
    /// A separate child process per case, deliberately: `std::env::set_var` is
    /// process-global and this crate forbids `unsafe`, so a config-directory
    /// override can only be tested through a spawn.
    fn command_with(&self, extra: &[(&str, &std::path::Path)], arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("KALEIDOSCOPE_USER_HOME", &self.home)
            .env("KALEIDOSCOPE_CONFIG_HOME", &self.config_home)
            .env("KALEIDOSCOPE_DATA_HOME", &self.data_home)
            .env("KSCOPE_PROFILE_HOME", &self.profile_home)
            .arg("--engine")
            .arg(&self.engine)
            .args(arguments);
        for (name, value) in CANARIES {
            command.env(name, value);
        }
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    /// `command`, but standing where a SESSION stands and with stdin closed.
    ///
    /// The `SessionStart` hook resolves the project from its working directory
    /// when the harness sends it no input, so a hook test that inherits cargo's
    /// working directory reads the DEVELOPER's real `.mcp.json` and reports on
    /// whatever engine that names. Closing stdin matters for the same class of
    /// reason: inherited from the test harness it is not a tty, but it is also
    /// never written to, and the hook would spend its stdin budget waiting.
    fn hook(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("KALEIDOSCOPE_USER_HOME", &self.home)
            .env("KALEIDOSCOPE_CONFIG_HOME", &self.config_home)
            .env("KALEIDOSCOPE_DATA_HOME", &self.data_home)
            .env("KSCOPE_PROFILE_HOME", &self.profile_home)
            .current_dir(&self.project)
            .stdin(std::process::Stdio::null())
            .arg("--engine")
            .arg(&self.engine)
            .args(arguments);
        command.output().unwrap()
    }

    /// Register a native profile directly, bypassing `init`. Used by tests
    /// whose subject is a LATER step and which must not also exercise vault
    /// discovery -- notably the invalid-descriptor test, whose fixture returns
    /// a descriptor `init` itself would refuse.
    fn register(&self, name: &str, root: &std::path::Path, durability: &str) {
        fs::create_dir_all(&self.profile_home).unwrap();
        fs::create_dir_all(root.join("workspaces/wsp_secret")).unwrap();
        fs::write(
            root.join("manifest.json"),
            r#"{"schema_name":"filesystem.root-manifest","schema_version":1}"#,
        )
        .unwrap();
        fs::write(
            self.profile_home.join(name),
            format!("{}\n{durability}\n", root.display()),
        )
        .unwrap();
    }

    /// A fingerprint of the whole world -- home and project -- so "the refusal
    /// wrote nothing" is checkable rather than assumed. The manager's own state
    /// directory is excluded: it holds the profile and the vault, which a
    /// refusal in a LATER step does not roll back and is not supposed to.
    fn tree_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for root in [&self.home, &self.project] {
            let mut entries: Vec<PathBuf> = Vec::new();
            let mut stack = vec![root.clone()];
            while let Some(directory) = stack.pop() {
                let Ok(children) = fs::read_dir(&directory) else {
                    continue;
                };
                for child in children.flatten() {
                    let path = child.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        entries.push(path);
                    }
                }
            }
            entries.sort();
            for path in entries {
                hasher.update(path.to_string_lossy().as_bytes());
                hasher.update(fs::read(&path).unwrap_or_default());
            }
        }
        format!("{:x}", hasher.finalize())
    }

    /// Make the fake engine WALK for `where --root-only` instead of answering
    /// with the working directory.
    ///
    /// Rewritten IN PLACE rather than chained through a wrapper script: the
    /// launch descriptor the engine emits names its own absolute path, and the
    /// manager validates that against the executable it actually ran, so a
    /// wrapper produces "closed version-1 shape mismatch" and the test fails on
    /// the wrong thing.
    fn make_the_engine_walk(&self) {
        let script = fs::read_to_string(&self.engine).unwrap();
        let walked = script.replace(
            "      here=$(pwd)\n",
            "      here=$(pwd)\n      while [ \"$here\" != / ]; do\n        [ -f \"$here/CLAUDE.md\" ] && break\n        here=$(dirname \"$here\")\n      done\n",
        );
        assert_ne!(walked, script, "the where arm moved; this rewrite is stale");
        fs::write(&self.engine, walked).unwrap();
        fs::set_permissions(&self.engine, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn success(&self, arguments: &[&str]) -> Output {
        let output = self.command(arguments);
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn fake_engine_full_manager_flow_is_redacted_and_uses_closed_environment() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("vault-root-secret");
    let initialized = fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "default",
    ]);
    fixture.success(&["profile", "list"]);
    fixture.success(&["profile", "show", "default"]);
    fixture.success(&["profile", "use", "default"]);
    // Remove a throwaway profile, not the one the rest of this test uses: the
    // fake engine now keeps a real registry, so `remove` really removes.
    fixture.register(
        "scratch",
        &fixture.temp.path().join("scratch-vault"),
        "process-local",
    );
    fixture.success(&["profile", "remove", "scratch"]);
    fixture.success(&["profile", "use", "default"]);
    let config = fixture.success(&["config", "--profile", "default", "--json"]);
    let descriptor: Value = serde_json::from_slice(&config.stdout).unwrap();
    assert_eq!(descriptor["version"], 1);
    assert_eq!(descriptor["transport"], "stdio");
    assert_eq!(
        descriptor["args"],
        serde_json::json!(["mcp", "--profile", "default"])
    );
    assert_eq!(
        descriptor["tools"],
        serde_json::json!(["search", "remember"])
    );
    assert_eq!(descriptor["environment"], serde_json::json!({}));

    // `--scope project` is now EXPLICIT here. User scope became the default,
    // and every assertion below reads a file in `fixture.project`.
    let dry_run = fixture.success(&[
        "connect",
        "codex",
        "--profile",
        "default",
        "--scope",
        "project",
        "--project",
        fixture.project.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&dry_run.stdout).unwrap()["status"],
        "dry_run"
    );
    assert!(!fixture.project.join(".codex/config.toml").exists());
    for host in ["codex", "claude-code", "cursor", "opencode"] {
        fixture.success(&[
            "connect",
            host,
            "--profile",
            "default",
            "--scope",
            "project",
            "--project",
            fixture.project.to_str().unwrap(),
            "--yes",
        ]);
    }
    let doctor = fixture.success(&["doctor", "--project", fixture.project.to_str().unwrap()]);
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["offline"], true);
    assert_eq!(report["redacted"], true);

    let manager_config = fixture.config_home.join("manager.json");
    let mut published = vec![
        fs::read_to_string(manager_config).unwrap(),
        String::from_utf8(initialized.stdout).unwrap(),
        String::from_utf8(doctor.stdout).unwrap(),
    ];
    for path in [
        ".codex/config.toml",
        ".codex/config.toml.kaleidoscope-owner.json",
        ".mcp.json",
        ".mcp.json.kaleidoscope-owner.json",
        ".cursor/mcp.json",
        ".cursor/mcp.json.kaleidoscope-owner.json",
        "opencode.json",
        "opencode.json.kaleidoscope-owner.json",
    ] {
        published.push(fs::read_to_string(fixture.project.join(path)).unwrap());
    }
    let published = published.join("\n");
    for (_, secret) in CANARIES {
        assert!(!published.contains(secret), "leaked canary {secret}");
    }

    let log = fs::read_to_string(&fixture.log).unwrap();
    for expected in [
        "ARGS <init-profile>",
        "ARGS <profile> <list>",
        "ARGS <profile> <show>",
        "ARGS <profile> <remove>",
        "ARGS <profile> <launch>",
        "ARGS <--version>",
        "ARGS <public-contract>",
    ] {
        assert!(
            log.contains(expected),
            "missing engine invocation {expected}"
        );
    }
    let invocations = log
        .split("---\n")
        .filter(|entry| !entry.trim().is_empty())
        .collect::<Vec<_>>();
    assert!(!invocations.is_empty());
    for invocation in invocations {
        let environment = invocation.split_once('\n').unwrap().1;
        assert!(environment.contains(&format!(
            "KSCOPE_PROFILE_HOME={}",
            fixture.profile_home.display()
        )));
        for (name, secret) in CANARIES {
            assert!(
                !environment.contains(name),
                "passed forbidden variable {name}"
            );
            assert!(
                !environment.contains(secret),
                "passed forbidden canary {secret}"
            );
        }
        assert!(!environment.contains("KALEIDOSCOPE_DATA_HOME="));
    }
}

#[test]
fn friendly_init_without_arguments_uses_documented_local_defaults() {
    let fixture = Fixture::new(false);
    let initialized = fixture.success(&["init"]);
    let result: Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(result["status"], "initialized");
    assert_eq!(result["profile"]["name"], "default");
    assert_eq!(result["profile"]["root"], "<redacted>");
    assert_eq!(
        result["launch"]["tools"],
        serde_json::json!(["search", "remember"])
    );

    let expected_root = fixture.data_home.join("vaults/default");
    assert!(expected_root.parent().unwrap().is_dir());
    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains(&format!(
        "ARGS <init-profile> <default> <{}>",
        expected_root.display()
    )));
    assert!(!log.contains("KALEIDOSCOPE_DATA_HOME="));
}

#[test]
fn instruction_cli_requires_confirmation_and_honors_dry_run() {
    let temp = TempDir::new().unwrap();
    let project = fs::canonicalize(temp.path()).unwrap();
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kaleidoscope"))
            .env_clear()
            .env("HOME", &project)
            .args(arguments)
            .output()
            .unwrap()
    };
    let target = project.join("AGENTS.md");
    let dry = run(&[
        "instructions",
        "install",
        "agents",
        "--project",
        project.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(dry.status.success());
    assert!(!target.exists());

    let cancelled = run(&[
        "instructions",
        "install",
        "agents",
        "--project",
        project.to_str().unwrap(),
    ]);
    assert!(!cancelled.status.success());
    assert!(!target.exists());

    let installed = run(&[
        "instructions",
        "install",
        "agents",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    assert!(installed.status.success());
    assert!(
        fs::read_to_string(&target)
            .unwrap()
            .contains("kaleidoscope-manager-v1")
    );

    let remove_dry = run(&[
        "instructions",
        "remove",
        "agents",
        "--project",
        project.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(remove_dry.status.success());
    assert!(target.exists());
    let removed = run(&[
        "instructions",
        "remove",
        "agents",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    assert!(removed.status.success());
    assert!(!target.exists());
}

#[test]
fn invalid_launch_descriptor_is_refused_before_host_write() {
    let fixture = Fixture::new(true);
    fixture.register(
        "default",
        &fixture.temp.path().join("descriptor-vault"),
        "process-local",
    );
    let output = fixture.command(&[
        "connect",
        "cursor",
        "--profile",
        "default",
        "--project",
        fixture.project.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("closed version-1 shape mismatch"));
    assert!(!fixture.project.join(".cursor/mcp.json").exists());
}

#[test]
fn account_cli_surface_never_resolves_engine_and_fails_closed_without_provider() {
    let fixture = Fixture::new(false);
    let external_identity = "55555555-5555-4555-8555-555555555555";
    let device = "33333333-3333-4333-8333-333333333333";
    for arguments in [
        vec!["login"],
        vec!["login", "--device"],
        vec!["status", "--json"],
        vec!["logout"],
        vec!["logout", "--local-only"],
        vec!["logout", "--all-devices"],
        vec!["account", "link", "github"],
        vec!["account", "identities"],
        vec!["account", "unlink", external_identity],
        vec!["account", "revoke-session"],
        vec!["devices", "list"],
        vec!["devices", "revoke", device],
    ] {
        let output = fixture.command(&arguments);
        assert!(
            !output.status.success(),
            "unexpected success for {arguments:?}"
        );
        let published = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(published.contains("account provider is not configured"));
        for (_, secret) in CANARIES {
            assert!(
                !published.contains(secret),
                "leaked account canary {secret}"
            );
        }
    }
    assert!(
        !fixture.log.exists(),
        "account commands invoked the memory engine"
    );
    assert!(fs::read_dir(&fixture.config_home).unwrap().next().is_none());
}

#[test]
fn profile_account_binding_is_manager_local_nonsecret_and_never_resolves_engine() {
    let fixture = Fixture::new(false);
    let account_id = "11111111-1111-4111-8111-111111111111";
    let bound = fixture.success(&["profile", "account", "bind", account_id, "default"]);
    let bound: Value = serde_json::from_slice(&bound.stdout).unwrap();
    assert_eq!(bound["status"], "bound");
    assert_eq!(bound["profile"], "default");
    assert_eq!(bound["account_id"], account_id);

    let shown = fixture.success(&["profile", "account", "show", "default"]);
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["account_id"], account_id);

    let manager_config = fs::read_to_string(fixture.config_home.join("manager.json")).unwrap();
    assert!(manager_config.contains(account_id));
    assert!(manager_config.contains("account_bindings"));
    for (_, secret) in CANARIES {
        assert!(!manager_config.contains(secret), "leaked canary {secret}");
    }
    assert!(
        !fixture.log.exists(),
        "profile-account commands invoked the memory engine"
    );

    let unbound = fixture.success(&["profile", "account", "unbind", "default"]);
    let unbound: Value = serde_json::from_slice(&unbound.stdout).unwrap();
    assert_eq!(unbound["status"], "unbound");
    let shown = fixture.success(&["profile", "account", "show", "default"]);
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["account_id"], Value::Null);
}

#[test]
#[ignore = "set KALEIDOSCOPE_LIVE_ENGINE and KALEIDOSCOPE_EXPECTED_ENGINE_SHA256"]
fn live_bundled_engine_contract() {
    let engine = PathBuf::from(std::env::var_os("KALEIDOSCOPE_LIVE_ENGINE").unwrap());
    let expected_hash = std::env::var("KALEIDOSCOPE_EXPECTED_ENGINE_SHA256").unwrap();
    let actual_hash = format!("{:x}", Sha256::digest(fs::read(&engine).unwrap()));
    assert_eq!(actual_hash, expected_hash);
    let temp = TempDir::new().unwrap();
    let canonical_temp = fs::canonicalize(temp.path()).unwrap();
    let home = canonical_temp.join("home");
    let project = canonical_temp.join("project");
    let profile_home = canonical_temp.join("profiles");
    let config_home = canonical_temp.join("config");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&config_home).unwrap();
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kaleidoscope"))
            .env_clear()
            .env("HOME", &home)
            .env("KALEIDOSCOPE_USER_HOME", &home)
            .env("KALEIDOSCOPE_CONFIG_HOME", &config_home)
            .env("KSCOPE_PROFILE_HOME", &profile_home)
            .arg("--engine")
            .arg(&engine)
            .args(arguments)
            .output()
            .unwrap()
    };
    let root = canonical_temp.join("vault");
    let initialized = run(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "default",
    ]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let config = run(&["config", "--profile", "default", "--json"]);
    assert!(
        config.status.success(),
        "{}",
        String::from_utf8_lossy(&config.stderr)
    );
    let descriptor: Value = serde_json::from_slice(&config.stdout).unwrap();
    assert_eq!(descriptor["version"], 1);
    assert_eq!(descriptor["transport"], "stdio");
    assert_eq!(
        descriptor["command"],
        fs::canonicalize(engine).unwrap().to_str().unwrap()
    );
    assert_eq!(
        descriptor["args"],
        serde_json::json!(["mcp", "--profile", "default"])
    );
    assert_eq!(
        descriptor["tools"],
        serde_json::json!(["search", "remember"])
    );
    assert_eq!(descriptor["environment"], serde_json::json!({}));
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

// ---------------------------------------------------------------------------
// INIT: vault discovery, the fork guard, and the three outcomes.
//
// Every test below names the observation that makes a broken implementation
// fail. A test whose pass condition is "no error was raised" passes hardest
// when the check itself is broken.
// ---------------------------------------------------------------------------

fn workspace_count(root: &std::path::Path) -> usize {
    fs::read_dir(root.join("workspaces")).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("wsp_"))
            .count()
    })
}

/// T-B1. The falsifier is not the exit code: it is that a real vault appears at
/// the named root with exactly one workspace, and that the resulting profile
/// launches. A create that silently produced nothing would pass a rc-only test.
#[test]
fn init_on_a_clean_tree_creates_exactly_one_workspace() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("fresh-vault");
    let output = fixture.success(&["init", "--root", root.to_str().unwrap()]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "initialized");
    assert_eq!(value["vault"]["created"], true);
    assert_eq!(value["vault"]["workspaces"], 1);
    assert_eq!(workspace_count(&root), 1);
    fixture.success(&["config", "--json"]);
}

/// T-B2, THE FORK BUG. Measured on the real engine 2026-08-26: `init --root
/// <an existing vault>` returned rc=0 and "initialized" while adding a second
/// workspace, and `kscope profile import` afterwards refused with
/// "vault has 2 workspaces", so the recovery path was gone too.
///
/// The workspace count before and after is the DIRECT measurement of the bug.
/// It read 1 -> 2. It must now read 1 -> 1, and the status must say `adopted`,
/// not `initialized` -- an implementation that adopted but still reported
/// `initialized` would be lying about what it did.
#[test]
fn init_on_an_existing_vault_adopts_and_does_not_fork_it() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("existing-vault");
    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "first",
    ]);
    let before = workspace_count(&root);
    assert_eq!(before, 1, "the seed vault must start with one workspace");

    let output = fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "second",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "adopted", "the vault must be ADOPTED");
    assert_eq!(value["vault"]["created"], false);
    assert_eq!(
        workspace_count(&root),
        before,
        "the vault was FORKED: {before} workspace(s) before, {} after",
        workspace_count(&root)
    );
    // The adopted profile must be usable, which the forked one is not.
    fixture.success(&["config", "--profile", "second", "--json"]);
}

/// T-B3. Today this was rc=2 with `profile already exists` and no way forward.
/// Asserts the descriptor as well as the code, so an implementation that
/// returned rc=0 and an empty body would fail.
#[test]
fn init_twice_is_already_initialized_and_returns_the_same_descriptor() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("twice-vault");
    let first = fixture.success(&["init", "--root", root.to_str().unwrap()]);
    let second = fixture.success(&["init", "--root", root.to_str().unwrap()]);
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(first["status"], "initialized");
    assert_eq!(second["status"], "already_initialized");
    assert_eq!(first["launch"], second["launch"]);
    assert_eq!(workspace_count(&root), 1);
}

/// T-B4. The no-change half is what stops a "refuse after mutating"
/// implementation passing: the profile registry file is digested before and
/// after.
#[test]
fn init_with_a_root_that_differs_from_an_existing_profile_refuses_and_changes_nothing() {
    let fixture = Fixture::new(false);
    let first = fixture.temp.path().join("bound-vault");
    let other = fixture.temp.path().join("other-vault");
    fixture.success(&["init", "--root", first.to_str().unwrap()]);
    fs::create_dir_all(other.join("workspaces/wsp_secret")).unwrap();
    fs::write(
        other.join("manifest.json"),
        r#"{"schema_name":"filesystem.root-manifest","schema_version":1}"#,
    )
    .unwrap();
    let registry = fixture.profile_home.join("default");
    let before = fs::read(&registry).unwrap();

    let output = fixture.command(&["init", "--root", other.to_str().unwrap()]);
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains(first.to_str().unwrap()), "{message}");
    assert!(message.contains(other.to_str().unwrap()), "{message}");
    assert_eq!(
        fs::read(&registry).unwrap(),
        before,
        "the refusal mutated the profile registry"
    );
    assert_eq!(workspace_count(&other), 1, "the refusal touched the vault");
}

/// T-B5. Asserts the CONTENT of the refusal, not just rc=2: an implementation
/// that refused with a bare message would pass a code-only test and leave the
/// user with no way forward.
#[test]
fn several_candidates_refuse_and_list_every_one_of_them() {
    let fixture = Fixture::new(false);
    let alpha = fixture.temp.path().join("alpha-vault");
    let beta = fixture.temp.path().join("beta-vault");
    fixture.success(&[
        "init",
        "--root",
        alpha.to_str().unwrap(),
        "--profile",
        "alpha",
    ]);
    fixture.success(&[
        "init",
        "--root",
        beta.to_str().unwrap(),
        "--profile",
        "beta",
    ]);

    let output = fixture.command(&["init", "--profile", "third"]);
    assert!(!output.status.success(), "several candidates must refuse");
    let message = String::from_utf8_lossy(&output.stderr);
    for root in [&alpha, &beta] {
        assert!(
            message.contains(root.to_str().unwrap()),
            "the refusal omits {}: {message}",
            root.display()
        );
    }
    assert!(message.contains("registered profile"), "{message}");
    assert!(message.contains("--root"), "{message}");
    assert!(message.contains("Nothing was created"), "{message}");
    assert!(
        !fixture.profile_home.join("third").exists(),
        "the refusal created a profile anyway"
    );
}

/// T-B6. The one case where the user asked for the destructive thing. Forking
/// is never what "create" meant, so this refuses even under `--create`.
#[test]
fn create_over_an_existing_vault_refuses_even_when_explicitly_asked() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("guarded-vault");
    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "first",
    ]);
    let before = workspace_count(&root);

    let output = fixture.command(&[
        "init",
        "--create",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "forced",
    ]);
    assert!(!output.status.success(), "--create must refuse to fork");
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("FORK"), "{message}");
    assert_eq!(
        workspace_count(&root),
        before,
        "--create forked the vault anyway"
    );
}

/// T-B7. Forces the disagreement rather than asserting it cannot happen: a
/// directory whose manifest the PROBE accepts but which the engine refuses
/// (two workspaces). The engine's message must come back verbatim, and init
/// must NOT fall back to creating.
#[test]
fn the_probe_never_decides_alone_and_the_engine_wins() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("two-workspace-vault");
    fs::create_dir_all(root.join("workspaces/wsp_one")).unwrap();
    fs::create_dir_all(root.join("workspaces/wsp_two")).unwrap();
    fs::write(
        root.join("manifest.json"),
        r#"{"schema_name":"filesystem.root-manifest","schema_version":1}"#,
    )
    .unwrap();

    let output = fixture.command(&["init", "--root", root.to_str().unwrap()]);
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("vault has 2 workspaces"),
        "the engine's own refusal must be reported verbatim: {message}"
    );
    assert!(
        !fixture.profile_home.join("default").exists(),
        "init fell back to creating after the engine refused"
    );
    assert_eq!(workspace_count(&root), 2, "the refusal touched the vault");
}

// ---------------------------------------------------------------------------
// INIT CHAINING, HARNESS WIRING, AND TEARDOWN
// ---------------------------------------------------------------------------

/// Digest every file under `directory`, so a file an implementation forgot
/// about shows up as an extra PATH rather than as a silent difference.
fn tree_digest_map(directory: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    fn walk(
        base: &std::path::Path,
        current: &std::path::Path,
        out: &mut std::collections::BTreeMap<String, String>,
    ) {
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if let Ok(bytes) = fs::read(&path) {
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                out.insert(relative, format!("{:x}", Sha256::digest(&bytes)));
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(directory, directory, &mut out);
    out
}

/// T-B15 and T-B17 and T-B21 in one flow, because they are the same run.
///
/// A whole-tree digest map before and after, so `teardown` is measured by what
/// it left behind rather than by its own report. The "vault untouched" half
/// stops a teardown that helpfully deleted data.
#[test]
#[allow(clippy::too_many_lines)]
fn init_wires_a_harness_and_teardown_reverses_every_byte_of_it() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("wired-vault");
    let project = &fixture.project;

    // Pre-existing, user-authored files with awkward formatting: keys out of
    // alphabetical order and four-space indentation, which is exactly what the
    // old reserialising path destroyed.
    fs::write(
        project.join("CLAUDE.md"),
        "# My project\n\nNotes without a trailing newline",
    )
    .unwrap();
    fs::write(
        project.join(".mcp.json"),
        "{\n    \"mcpServers\": {\n        \"my-own-server\": {\n            \"command\": \"zzz\",\n            \"args\": []\n        }\n    }\n}\n",
    )
    .unwrap();
    fs::create_dir_all(project.join(".claude")).unwrap();
    fs::write(
        project.join(".claude/settings.json"),
        "{\n    \"theme\": \"dark\",\n    \"alwaysThinkingEnabled\": true\n}\n",
    )
    .unwrap();
    let before = tree_digest_map(project);

    let output = fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let steps = value["steps"].as_array().unwrap();
    let named = |name: &str| {
        steps
            .iter()
            .find(|step| step["step"] == name)
            .unwrap_or_else(|| panic!("no {name} step in {value}"))
            .clone()
    };
    for name in ["connect", "instructions", "skill", "hook"] {
        assert_eq!(named(name)["status"], "applied", "{name} did not apply");
    }

    // T-B17: the skill lands where Claude Code reads it, and the instruction
    // block installed for the same host names that same path. Two artefacts
    // cross-checked against each other -- they disagreed before this change.
    let skill = project.join(".claude/skills/use-kaleidoscope/SKILL.md");
    assert!(
        skill.exists(),
        "the skill is not where Claude Code reads it"
    );
    assert!(
        !project
            .join(".agents/skills/use-kaleidoscope/SKILL.md")
            .exists(),
        "the skill was also written where Claude Code does not read it"
    );
    let claude_md = fs::read_to_string(project.join("CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains(".claude/skills/use-kaleidoscope/SKILL.md"),
        "CLAUDE.md points at a path the skill is not at:\n{claude_md}"
    );
    assert!(claude_md.contains("# My project"), "user text lost");

    // T-B18: the installed skill is byte-identical to the shipped one.
    assert_eq!(
        fs::read_to_string(&skill).unwrap(),
        include_str!("../skills/use-kaleidoscope/SKILL.md"),
        "the installed skill differs from the shipped one"
    );

    // The hook entry is in the shareable settings.json, not settings.local.json.
    let settings: Value =
        serde_json::from_slice(&fs::read(project.join(".claude/settings.json")).unwrap()).unwrap();
    assert_eq!(settings["theme"], "dark", "the user's settings were lost");
    assert_eq!(
        settings["hooks"]["SessionStart"].as_array().unwrap().len(),
        1
    );
    assert!(
        !project.join(".claude/settings.local.json").exists(),
        "the hook was written into the personal, gitignored file"
    );

    let teardown = fixture.success(&[
        "teardown",
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let teardown: Value = serde_json::from_slice(&teardown.stdout).unwrap();
    for step in teardown["steps"].as_array().unwrap() {
        if step["status"] == "applied" {
            assert_eq!(
                step["restore"], "byte_identical",
                "{} took the structural tier where the exact one was expected: {step}",
                step["step"]
            );
        }
    }
    assert_eq!(teardown["vault"], "untouched");
    assert_eq!(teardown["profile"], "untouched");

    assert_eq!(
        tree_digest_map(project),
        before,
        "teardown did not restore the project tree byte-identically"
    );
    // The vault and the profile survive, because teardown removes host wiring
    // only. A teardown that helpfully deleted data fails here.
    assert_eq!(workspace_count(&root), 1, "teardown touched the vault");
    assert!(
        fixture.profile_home.join("default").exists(),
        "teardown removed the profile"
    );
}

/// T-B21: codex and opencode share AGENTS.md, so it is installed ONCE. The
/// receipt is per-target, not per-host, and the second install is a no-op.
/// Counts occurrences of the marker rather than trusting the report.
#[test]
fn agents_md_is_installed_once_for_codex_and_opencode_together() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("shared-agents-vault");
    let project = &fixture.project;
    let output = fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "codex",
        "--host",
        "opencode",
        "--scope",
        "project",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let instruction_steps: Vec<&Value> = value["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["step"] == "instructions")
        .collect();
    assert_eq!(instruction_steps.len(), 2, "one step per host");
    assert_eq!(instruction_steps[0]["status"], "applied");
    assert_eq!(
        instruction_steps[1]["status"], "unchanged",
        "AGENTS.md was installed twice"
    );
    let agents = fs::read_to_string(project.join("AGENTS.md")).unwrap();
    assert_eq!(
        agents.matches("instruction=agents -->").count(),
        2,
        "expected exactly one owned block (open + close marker)"
    );

    // The skill is shared for the same reason: both harnesses read
    // `.agents/skills/`. The receipt is keyed by PATH, not by the installing
    // host -- recording the host made the second harness refuse its own file.
    let skill_steps: Vec<&Value> = value["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["step"] == "skill")
        .collect();
    assert_eq!(skill_steps[0]["status"], "applied");
    assert_eq!(
        skill_steps[1]["status"], "unchanged",
        "the shared .agents skill was installed twice"
    );
    assert!(
        project
            .join(".agents/skills/use-kaleidoscope/SKILL.md")
            .exists()
    );
    assert!(
        !project
            .join(".claude/skills/use-kaleidoscope/SKILL.md")
            .exists(),
        "a Claude Code skill was installed for hosts that do not read it"
    );

    // And the round trip still holds with two hosts sharing two files.
    let teardown = fixture.success(&[
        "teardown",
        "--host",
        "codex",
        "--host",
        "opencode",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let teardown: Value = serde_json::from_slice(&teardown.stdout).unwrap();
    assert_eq!(teardown["status"], "removed", "{teardown}");
    assert!(!project.join("AGENTS.md").exists());
    assert!(
        !project.join(".agents").exists(),
        "an emptied managed directory survived"
    );
}

/// T-B22: RUN the hook, exactly as the settings file spells it. A hook entry
/// written into a settings file that nothing executes is the unwired-mitigation
/// defect, and only invoking it can tell the difference.
///
/// T-B24 rides along, and its subject CHANGED. It used to assert the hook made
/// no gated engine call at all (`mcp`, `context`, `call`, `serve`). The hook now
/// deliberately makes two of those, because the alternative was the defect this
/// change exists to fix: it speaks MCP to the registered server rather than
/// asserting "connected" without checking, and it retrieves memories rather
/// than emitting a reminder to go and get some.
///
/// So the property under test is now the narrower and more useful one:
///
///  * the probe REALLY RAN -- `ARGS <mcp>` is in the log, recorded by the child
///    itself, which is what separates a wired probe from a printed claim;
///  * the hook never WRITES -- no `remember` reaches the engine, from a hook
///    that fires on every startup, resume, clear and compact;
///  * `serve` is never invoked, because a session start must not leave a
///    long-lived server behind it.
#[test]
fn the_installed_hook_actually_fires_and_probes_but_never_writes() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("hook-vault");
    let project = &fixture.project;
    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let settings: Value =
        serde_json::from_slice(&fs::read(project.join(".claude/settings.json")).unwrap()).unwrap();
    let entry = &settings["hooks"]["SessionStart"][0];
    assert_eq!(entry["matcher"], "startup|resume|clear|compact");
    let command = entry["hooks"][0]["command"].as_str().unwrap().to_owned();

    // Truncate the log so the assertion below sees only the hook's own calls.
    fs::write(&fixture.log, "").unwrap();

    let parts: Vec<&str> = command.split(' ').collect();
    let executable = parts[0];
    let mut invocation = Command::new(executable);
    invocation
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .env("KALEIDOSCOPE_CONFIG_HOME", &fixture.config_home)
        .env("KALEIDOSCOPE_DATA_HOME", &fixture.data_home)
        .env("KSCOPE_PROFILE_HOME", &fixture.profile_home)
        .env("KALEIDOSCOPE_ENGINE", &fixture.engine)
        // The SESSION's directory, not the test harness's. Without this the
        // hook falls back to the cargo working directory and reads the
        // DEVELOPER's real `.mcp.json` -- which it did, and reported on a
        // stale engine from another test's deleted temporary directory.
        .current_dir(project)
        .stdin(std::process::Stdio::null())
        .args(&parts[1..]);
    let output = invocation.output().unwrap();

    assert!(
        output.status.success(),
        "the hook exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.len() <= 4096,
        "the hook emitted {} bytes",
        output.stdout.len()
    );
    let emitted: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("hook stdout is not JSON ({error}): {:?}", output.stdout));
    assert_eq!(
        emitted["hookSpecificOutput"]["hookEventName"], "SessionStart",
        "wrong hook event name: {emitted}"
    );
    let context = emitted["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext must be a string");
    assert!(!context.is_empty());
    assert!(
        context.contains("search") && context.contains("remember"),
        "the context must name the public tools: {context}"
    );
    // The machine-readable verdict, on the first line, is the whole point of
    // item 3: a later session is audited against it rather than believing a
    // sentence.
    let facts: Value = serde_json::from_str(context.lines().next().unwrap())
        .expect("the first line of the context must be the machine-readable verdict");
    assert!(
        facts["tools_visible"].is_boolean(),
        "no tools_visible in {facts}"
    );
    assert_eq!(
        facts["registration"]["source"],
        Value::String(project.join(".mcp.json").display().to_string()),
        "the probe reported on the wrong registration: {facts}"
    );

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(
        log.contains("ARGS <profile> <launch>"),
        "the hook made no engine call at all, so this test proves nothing: {log}"
    );
    assert!(
        log.contains("ARGS <mcp>"),
        "the MCP probe never ran, so the verdict is a claim rather than a measurement: {log}"
    );
    // The hook reads. It must never write, and it must never leave a server
    // running behind a session start.
    for forbidden in ["<remember>", "ARGS <serve>"] {
        assert!(
            !log.contains(forbidden),
            "the hook invoked {forbidden}: {log}"
        );
    }
}

/// T-B23. Both halves: an exit-0-with-empty-output implementation fails the
/// content assertion, an exit-1 implementation fails the code assertion.
///
/// Asserted on the machine-readable field rather than on a phrase, so the
/// wording of the prose can change without this test either breaking or --
/// worse -- passing on a sentence that no longer says the profile is broken.
#[test]
fn the_hook_reports_a_broken_profile_instead_of_failing() {
    let fixture = Fixture::new(false);
    let output = fixture.hook(&["hook", "session-start", "--profile", "nonexistent"]);
    assert!(
        output.status.success(),
        "a hook that exits non-zero is a hook the user turns off"
    );
    let emitted: Value = serde_json::from_slice(&output.stdout).unwrap();
    let context = emitted["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    let facts: Value = serde_json::from_str(context.lines().next().unwrap()).unwrap();
    assert_ne!(
        facts["profile_launch"],
        Value::String("ok".to_owned()),
        "a broken profile must be NAMED, not swallowed: {facts}"
    );
    assert!(
        facts["profile_launch"]
            .as_str()
            .is_some_and(|detail| detail.contains("not registered") || detail.contains("refused")),
        "the engine's own reason must travel: {facts}"
    );
    assert!(context.contains("doctor"), "{context}");
}

/// THE constraint on this hook. Every stage fails at once -- no engine, no
/// registration, no project, no vault -- and the hook still exits 0 and still
/// emits a parseable, non-empty verdict.
///
/// It exists because `run_hook` used to return `Err` for a mis-parsed
/// `--profile` and for any unrecognised argument, and `main` turns `Err` into
/// exit 2. One typo in the settings entry was the difference between a hook
/// that reports a problem and a hook the harness reports as broken -- which is
/// a hook the user turns off, taking the working memory with it.
#[test]
fn the_hook_exits_zero_when_every_stage_fails() {
    let fixture = Fixture::new(false);
    let empty = fixture.temp.path().join("no-project-here");
    fs::create_dir_all(&empty).unwrap();
    for arguments in [
        // The ordinary shape, with nothing behind it.
        vec!["hook", "session-start", "--profile", "default"],
        // `--profile` with no value: a parse error that used to be exit 2.
        vec!["hook", "session-start", "--profile"],
        // An argument nothing recognises: also exit 2, previously.
        vec![
            "hook",
            "session-start",
            "--profile",
            "default",
            "--nonsense",
        ],
        // No profile at all.
        vec!["hook", "session-start"],
        // Retrieval explicitly off, so the no-write path is covered too.
        vec!["hook", "session-start", "--no-memories"],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
        command
            .env_clear()
            .env("HOME", &empty)
            .env("KALEIDOSCOPE_USER_HOME", &empty)
            .env("KALEIDOSCOPE_CONFIG_HOME", &empty)
            .env("KSCOPE_PROFILE_HOME", &empty)
            .env("KALEIDOSCOPE_ENGINE", empty.join("no-such-engine"))
            .current_dir(&empty)
            .stdin(std::process::Stdio::null())
            .args(&arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "`{}` exited {:?}: {}",
            arguments.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        let emitted: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "`{}` emitted unparseable stdout ({error}): {}",
                arguments.join(" "),
                String::from_utf8_lossy(&output.stdout)
            )
        });
        let context = emitted["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("additionalContext must be a string on every failure path");
        let facts: Value = serde_json::from_str(context.lines().next().unwrap())
            .expect("the verdict must survive every failure path");
        assert_eq!(
            facts["tools_visible"],
            Value::Bool(false),
            "nothing is reachable here: {facts}"
        );
        assert!(
            context.contains("kscope"),
            "the fallback must still be named: {context}"
        );
    }
}

/// T-B9. All four hosts x both scopes, each with a pre-existing user-authored
/// config whose keys are out of alphabetical order and indented with four
/// spaces. `cmp`-level byte equality AND the reported tier -- a Tier-2 result
/// that coincidentally matched still fails.
#[test]
fn connect_then_disconnect_is_byte_identical_for_every_host_and_scope() {
    for host in ["codex", "claude-code", "cursor", "opencode"] {
        for scope in ["user", "project"] {
            let fixture = Fixture::new(false);
            let root = fixture.temp.path().join("roundtrip-vault");
            fixture.success(&["init", "--root", root.to_str().unwrap()]);
            let target = match (host, scope) {
                ("codex", "user") => fixture.home.join(".codex/config.toml"),
                ("codex", _) => fixture.project.join(".codex/config.toml"),
                ("claude-code", "user") => fixture.home.join(".claude.json"),
                ("claude-code", _) => fixture.project.join(".mcp.json"),
                ("cursor", "user") => fixture.home.join(".cursor/mcp.json"),
                ("cursor", _) => fixture.project.join(".cursor/mcp.json"),
                ("opencode", "user") => fixture.home.join(".config/opencode/opencode.json"),
                _ => fixture.project.join("opencode.json"),
            };
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            let seed = if target.extension().is_some_and(|value| value == "toml") {
                "# my own notes\n[other_tool]\nzebra = 1\napple = 2\n".to_owned()
            } else {
                "{\n    \"zebra\": 1,\n    \"apple\": {\n        \"nested\": true\n    }\n}\n"
                    .to_owned()
            };
            fs::write(&target, &seed).unwrap();
            let before = fs::read(&target).unwrap();

            fixture.success(&[
                "connect",
                host,
                "--scope",
                scope,
                "--project",
                fixture.project.to_str().unwrap(),
                "--yes",
            ]);
            assert_ne!(
                fs::read(&target).unwrap(),
                before,
                "{host}/{scope}: connect changed nothing, so the round-trip proves nothing"
            );

            let output = fixture.success(&[
                "disconnect",
                host,
                "--scope",
                scope,
                "--project",
                fixture.project.to_str().unwrap(),
                "--yes",
            ]);
            let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                summary["restore"], "byte_identical",
                "{host}/{scope}: took the structural tier where the exact one was expected"
            );
            assert_eq!(
                fs::read(&target).unwrap(),
                before,
                "{host}/{scope}: the config was not restored byte-identically"
            );
            assert!(
                !fixture
                    .temp
                    .path()
                    .join(format!("{}.kaleidoscope-backup", target.display()))
                    .exists(),
                "{host}/{scope}: a redundant backup survived an exact restore"
            );
        }
    }
}

/// T-B29. An absence claim needs an attempt to make it fire, and the record of
/// that attempt has to be committed or it is not a record. This asserts the
/// ATTEMPT was written down -- not that the absence is true, which no test can
/// establish. It fails if someone adds a harness without checking, or removes a
/// row while leaving the code that depends on it.
#[test]
fn hook_absence_is_attempted_and_recorded_for_every_harness() {
    let compatibility = include_str!("../COMPATIBILITY.md");
    let table = compatibility
        .split_once("## Harness hook mechanisms")
        .expect("COMPATIBILITY.md must carry the hook table")
        .1;
    for host in ["claude-code", "codex", "cursor", "opencode"] {
        let row = table
            .lines()
            .find(|line| line.starts_with(&format!("| {host} |")))
            .unwrap_or_else(|| panic!("no hook row for {host}"));
        assert!(
            row.contains("2026-"),
            "{host}'s hook row carries no check date: {row}"
        );
        // A markdown row both starts and ends with `|`, so the split yields an
        // empty cell at each end. The "how" column is the last NON-EMPTY one.
        let how = row
            .split('|')
            .map(str::trim)
            .rfind(|cell| !cell.is_empty())
            .unwrap_or_default();
        assert!(
            how.len() > 60,
            "{host}'s hook row does not say HOW it was checked: {how}"
        );
    }
}

/// A teardown that reports `byte_identical` must leave NOTHING behind, on every
/// host, including when the manager created every file it touched.
///
/// `init_wires_a_harness_and_teardown_reverses_every_byte_of_it` compares the
/// whole tree and was green while all four hosts leaked a backup, because its
/// project already HAD a `.mcp.json`: with a pre-existing file the removal
/// takes the `backup_is_pre` branch, which deletes the backup. The leak was on
/// the OTHER branch -- the one where the manager created the file, so no backup
/// existed at install time and `apply` minted one on the way out that nothing
/// removed. An empty project is what puts every host on that branch.
///
/// Each leftover named the profile and the absolute engine path, which is
/// exactly what `profile_summary` redacts from stdout.
#[test]
fn teardown_leaves_no_orphan_when_the_manager_created_every_file() {
    for host in ["claude-code", "codex", "cursor", "opencode"] {
        let fixture = Fixture::new(false);
        let root = fixture.temp.path().join(format!("orphan-vault-{host}"));
        let project = fixture.temp.path().join(format!("orphan-project-{host}"));
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("app.py"), "print('hello')\n").unwrap();
        let before = tree_digest_map(&project);

        fixture.success(&[
            "init",
            "--root",
            root.to_str().unwrap(),
            "--host",
            host,
            "--scope",
            "project",
            "--project",
            project.to_str().unwrap(),
            "--yes",
        ]);

        // The control: init really did write something into this project, so an
        // empty diff below cannot come from a no-op init.
        assert_ne!(
            tree_digest_map(&project),
            before,
            "{host}: init wrote nothing, so the teardown assertion would be vacuous"
        );

        let teardown = fixture.success(&[
            "teardown",
            "--host",
            host,
            "--scope",
            "project",
            "--project",
            project.to_str().unwrap(),
            "--yes",
        ]);
        let teardown: Value = serde_json::from_slice(&teardown.stdout).unwrap();
        for step in teardown["steps"].as_array().unwrap() {
            if step["status"] == "applied" {
                assert_eq!(
                    step["restore"], "byte_identical",
                    "{host}: {} took the structural tier: {step}",
                    step["step"]
                );
            }
        }

        assert_eq!(
            tree_digest_map(&project),
            before,
            "{host}: teardown reported byte_identical and left files behind"
        );
    }
}

/// A structural (tier-2) removal must not destroy the user's pre-install backup.
///
/// `apply` wrote a backup unconditionally, and on a removal `self.original` is
/// the file AS THE MANAGER LEFT IT -- so the backup that held the user's
/// original 19 bytes was overwritten with 894 bytes of manager block, while the
/// planner's comment still called it "the user's only copy of the pre-edit
/// state". Measured before the fix; this test is that measurement.
#[test]
fn a_structural_removal_keeps_the_users_pre_install_backup() {
    let fixture = Fixture::new(false);
    let project = &fixture.project;
    let target = project.join("CLAUDE.md");
    let backup = project.join("CLAUDE.md.kaleidoscope-backup");
    fs::write(&target, "# My own CLAUDE.md\n").unwrap();
    let original = fs::read(&target).unwrap();

    fixture.success(&[
        "instructions",
        "install",
        "claude",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(
        fs::read(&backup).unwrap(),
        original,
        "the install did not capture the user's file"
    );

    // A user edit after install is what forces the structural tier.
    let mut edited = fs::read_to_string(&target).unwrap();
    edited.push_str("a user line added after install\n");
    fs::write(&target, &edited).unwrap();

    let removal = fixture.success(&[
        "instructions",
        "remove",
        "claude",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let removal: Value = serde_json::from_slice(&removal.stdout).unwrap();
    // The control: this really is the tier the defect lived on.
    assert_eq!(removal["restore"], "structural", "{removal}");

    assert_eq!(
        fs::read(&backup).unwrap(),
        original,
        "the removal overwrote the user's pre-install backup with manager bytes"
    );
    let kept = fs::read_to_string(&backup).unwrap();
    assert!(
        !kept.contains("kaleidoscope-manager"),
        "the backup holds a manager block:\n{kept}"
    );
    // And the user's own edit survived in the file itself.
    let after = fs::read_to_string(&target).unwrap();
    assert!(after.contains("a user line added after install"), "{after}");
    assert!(!after.contains("kaleidoscope-manager"), "{after}");
}

/// Reordering the keys of the manager's own entry must not wedge the project.
///
/// Two halves of one guard disagreed: `receipt.owned == current` is
/// order-insensitive, while `owned_sha256` was taken over an order-PRESERVING
/// re-serialisation of `current`. Any formatter with sort-keys, or a user
/// tidying `.mcp.json` by hand, produced a semantically identical document that
/// `teardown`, `teardown --force` and `disconnect` all refused with rc=2 -- and
/// restoring the original key order was the only way out.
#[test]
fn reordering_the_keys_of_the_managed_entry_does_not_wedge_the_connection() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("keyorder-vault");
    let project = &fixture.project;
    let config = project.join(".mcp.json");

    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);

    // Reorder the keys of the manager's own entry and change nothing else.
    let mut document: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    let entry = document["mcpServers"]["kaleidoscope"].clone();
    let object = entry.as_object().unwrap();
    let mut reordered = serde_json::Map::new();
    for key in ["args", "command", "type"] {
        if let Some(value) = object.get(key) {
            reordered.insert(key.to_owned(), value.clone());
        }
    }
    // The control: the reorder really did change the bytes and really did not
    // change the entry.
    assert_eq!(reordered.len(), object.len(), "the entry shape moved");
    let before_bytes = fs::read(&config).unwrap();
    document["mcpServers"]["kaleidoscope"] = Value::Object(reordered);
    let after_bytes = serde_json::to_vec_pretty(&document).unwrap();
    assert_ne!(before_bytes, after_bytes, "the reorder changed no bytes");
    fs::write(&config, &after_bytes).unwrap();

    fixture.success(&[
        "teardown",
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        !config.exists(),
        "teardown left the connection in place: {}",
        fs::read_to_string(&config).unwrap_or_default()
    );
}

/// `--force` must actually RUN on the marker states it exists for.
///
/// `find_owned_block`'s `?` fired before `force` was consulted, so a duplicated
/// block, a retyped marker and a deleted closing marker each refused
/// `instructions remove`, `instructions remove --force` and `instructions
/// install --force` alike, rc=2, with `doctor` saying only "local validation
/// failed". The block stayed in the user's CLAUDE.md permanently.
#[test]
fn force_unwedges_every_marker_state_that_used_to_be_permanent() {
    #[allow(clippy::type_complexity)]
    let mutations: [(&str, fn(&str) -> String); 3] = [
        ("the block appears twice", |text| format!("{text}{text}")),
        ("the start marker was retyped", |text| {
            text.replace(
                ">>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=claude",
                ">>> kaleidoscope-manager owner=kaleidoscope-manager-v1 instruction=CLAUDE",
            )
        }),
        ("the closing marker was deleted", |text| {
            let kept: Vec<&str> = text
                .lines()
                .filter(|line| !line.contains("<<< kaleidoscope-manager"))
                .collect();
            let mut out = kept.join("\n");
            out.push('\n');
            out
        }),
    ];

    for (label, mutate) in mutations {
        let fixture = Fixture::new(false);
        let project = &fixture.project;
        let target = project.join("CLAUDE.md");
        fs::write(&target, "# My project\n\nMy own notes.\n").unwrap();

        fixture.success(&[
            "instructions",
            "install",
            "claude",
            "--project",
            project.to_str().unwrap(),
            "--yes",
        ]);
        let installed = fs::read_to_string(&target).unwrap();
        let mutated = mutate(&installed);
        assert_ne!(mutated, installed, "{label}: the mutation changed nothing");
        fs::write(&target, &mutated).unwrap();

        // The control: WITHOUT --force this is refused, so the pass below is
        // not "the mutation was harmless".
        let plain = fixture.command(&[
            "instructions",
            "remove",
            "claude",
            "--project",
            project.to_str().unwrap(),
            "--yes",
        ]);
        assert!(
            !plain.status.success(),
            "{label}: the mutation did not need --force at all"
        );

        let forced = fixture.command(&[
            "instructions",
            "remove",
            "claude",
            "--project",
            project.to_str().unwrap(),
            "--yes",
            "--force",
        ]);
        assert!(
            forced.status.success(),
            "{label}: --force failed: {}",
            String::from_utf8_lossy(&forced.stderr)
        );
        let forced: Value = serde_json::from_slice(&forced.stdout).unwrap();
        // What was removed is DISCLOSED, not silently dropped.
        assert_eq!(forced["ownership"], "forced", "{label}: {forced}");
        assert_eq!(forced["discarded_user_edits"], true, "{label}: {forced}");
        assert!(
            forced["discarded_sha256"]
                .as_str()
                .is_some_and(|d| d.len() == 64),
            "{label}: no digest of the discarded bytes: {forced}"
        );

        let after = fs::read_to_string(&target).unwrap();
        assert!(
            !after.contains("kaleidoscope-manager"),
            "{label}: a manager marker survived --force:\n{after}"
        );
        assert!(
            after.contains("My own notes."),
            "{label}: the user's own text was lost:\n{after}"
        );
    }
}

/// The one marker state `--force` genuinely cannot repair must SAY so.
///
/// With both markers hand-edited there is nothing left in the file that
/// identifies the block, so no span can be computed. That is a real limit; what
/// was wrong was how it read. It surfaced as `InvalidOwnerReceipt`, whose
/// rendering then began "connection owner receipt is invalid" -- the wrong noun
/// for an agent instruction file, and it named no way forward at all. That
/// shared message now carries a manual remedy too, but this state deserves its
/// own, because the two files to delete are not the ones that message names.
#[test]
fn a_block_with_no_marker_left_names_the_state_and_both_files() {
    let fixture = Fixture::new(false);
    let project = &fixture.project;
    let target = project.join("CLAUDE.md");
    fs::write(&target, "# My project\n\nMy own notes.\n").unwrap();
    fixture.success(&[
        "instructions",
        "install",
        "claude",
        "--project",
        project.to_str().unwrap(),
        "--yes",
    ]);
    let installed = fs::read_to_string(&target).unwrap();
    fs::write(
        &target,
        installed.replace("kaleidoscope-manager owner=", "kaleidoscope-MANAGER owner="),
    )
    .unwrap();

    let refused = fixture.command(&[
        "instructions",
        "remove",
        "claude",
        "--project",
        project.to_str().unwrap(),
        "--yes",
        "--force",
    ]);
    assert!(!refused.status.success(), "this state is not repairable");
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !message.contains("connection owner receipt"),
        "an instruction file refused as a connection: {message}"
    );
    assert!(message.contains("no manager marker at all"), "{message}");
    assert!(message.contains("CLAUDE.md"), "{message}");
    assert!(
        message.contains(".kaleidoscope-instruction-owner.json"),
        "the remedy does not name the receipt to delete: {message}"
    );
}

/// `npm i -g` installs every `bin` entry as a SYMLINK, and the manager refused
/// exactly that shape -- so `@kleos-research/kaleidoscope`, the documented
/// distribution channel, put a `kscope` on PATH that the manager would not use.
///
/// Measured with the same binary reached two ways: through the symlink the hook
/// said "the engine could not be resolved", through the real path "connected".
/// The checks were made against the LINK while `Engine::new` canonicalised and
/// ran the TARGET, so they never described what was executed.
#[test]
fn an_npm_shaped_symlinked_engine_on_path_is_usable() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("symlink-vault");
    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "default",
    ]);

    // The control: the real path works, so a pass below is not "both fail".
    let direct = fixture.success(&["profile", "list"]);
    let direct: Value = serde_json::from_slice(&direct.stdout).unwrap();

    let npm_bin = fixture.temp.path().join("npm-prefix-bin");
    fs::create_dir_all(&npm_bin).unwrap();
    let link = npm_bin.join("kscope");
    std::os::unix::fs::symlink(&fixture.engine, &link).unwrap();
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the fixture did not create a symlink"
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
    command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .env("KALEIDOSCOPE_CONFIG_HOME", &fixture.config_home)
        .env("KALEIDOSCOPE_DATA_HOME", &fixture.data_home)
        .env("KSCOPE_PROFILE_HOME", &fixture.profile_home)
        .arg("--engine")
        .arg(&link)
        .arg("profile")
        .arg("list");
    let through_link = command.output().unwrap();
    assert!(
        through_link.status.success(),
        "a symlinked engine was refused: {}",
        String::from_utf8_lossy(&through_link.stderr)
    );
    let through_link: Value = serde_json::from_slice(&through_link.stdout).unwrap();
    assert_eq!(
        through_link, direct,
        "the symlink resolved to a different engine"
    );
}

/// When the engine cannot be resolved, the hook must say WHY.
///
/// `main.rs` did `Engine::resolve(engine).ok()`, so every distinct failure --
/// not installed, not executable, not a regular file -- arrived at the hook as
/// `None` and printed one sentence that reads as "not installed". The sibling
/// arm for a resolvable-but-unusable profile has always interpolated its error.
#[test]
fn the_hook_says_why_the_engine_could_not_be_resolved() {
    let fixture = Fixture::new(false);
    // A real file that is not executable: resolvable as a path, refusable as an
    // engine, and distinguishable from "not installed".
    let not_executable = fixture.temp.path().join("kscope-not-executable");
    fs::write(&not_executable, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&not_executable, fs::Permissions::from_mode(0o644)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
    command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .env("KALEIDOSCOPE_CONFIG_HOME", &fixture.config_home)
        .env("KSCOPE_PROFILE_HOME", &fixture.profile_home)
        .current_dir(&fixture.project)
        .stdin(std::process::Stdio::null())
        .arg("--engine")
        .arg(&not_executable)
        .args(["hook", "session-start", "--profile", "default"]);
    let output = command.output().unwrap();

    // Still exit 0: a hook that fails is a hook the user turns off.
    assert!(output.status.success(), "the hook exited non-zero");
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    let context = parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    let facts: Value = serde_json::from_str(context.lines().next().unwrap()).unwrap();
    assert_eq!(
        facts["engine"],
        Value::Null,
        "an unresolvable engine must be reported as such: {facts}"
    );
    // The REASON, not a generic "could not be resolved". Asserted on the
    // machine-readable field and on the prose, because the prose is what the
    // model reads and the field is what an audit reads.
    assert!(
        facts["profile_launch"]
            .as_str()
            .is_some_and(|detail| detail.contains("not executable")),
        "the hook swallowed the reason: {facts}"
    );
    assert!(
        context.contains("not executable"),
        "the reason did not reach the model: {context}"
    );
}

// =========================================================================
// Exit codes, project root, and the user-scope default.
// =========================================================================

/// `doctor` grades its own report through the exit code.
///
/// BOTH halves, in one test. It used to print `status: "issues"` and exit 0, so
/// "the report says there are problems" and "the command ran fine" were the
/// same observation to any caller that checked `$?`. Asserting only the issue
/// case would pass for an implementation that always returned 3.
#[test]
fn doctor_exits_three_on_an_issue_and_zero_when_clean() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("doctor-vault");
    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        fixture.project.to_str().unwrap(),
        "--yes",
    ]);

    // The exact string `init` prints in its own `next` array, read from that
    // array rather than retyped -- the command it advertises must parse.
    let clean = fixture.command(&[
        "doctor",
        "--json",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "clean doctor: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let report: Value = serde_json::from_slice(&clean.stdout).expect("doctor prints JSON");
    assert_eq!(report["status"], "ready");
    assert!(
        report["project"]["directory"].is_string(),
        "doctor must report the resolved project so it is inspectable without a write"
    );

    fs::write(
        fixture.project.join(".mcp.json.kaleidoscope-owner.json"),
        b"{}",
    )
    .unwrap();
    let broken = fixture.command(&[
        "doctor",
        "--json",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    assert_eq!(broken.status.code(), Some(3), "an issue must exit 3");
    let report: Value = serde_json::from_slice(&broken.stdout).unwrap();
    assert_eq!(report["status"], "issues");
    let issues = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| check["status"] == "issue")
        .count();
    assert!(issues >= 1, "exit 3 with no issue in the report");
}

/// Exit 3 must not leak out of `doctor`.
///
/// A source-level check, and the only thing standing between one new exit code
/// and a second meaning attached to it somewhere else.
#[test]
fn doctor_issues_is_constructed_exactly_once() {
    let mut sites = 0;
    for name in [
        "main.rs",
        "host.rs",
        "hooks.rs",
        "instructions.rs",
        "manager.rs",
        "doctor.rs",
        "engine.rs",
        "config.rs",
    ] {
        let source = fs::read_to_string(format!("src/{name}")).unwrap();
        // CONSTRUCTIONS only. `main` also names the variant, but in a match
        // PATTERN -- that is the one place allowed to read it, and counting it
        // would make this assertion impossible to satisfy.
        sites += source
            .matches("return Err(ManagerError::DoctorIssues(")
            .count();
    }
    assert_eq!(sites, 1, "DoctorIssues is constructed at {sites} sites");
}

/// EVERY refusal exits non-zero AND changes nothing.
///
/// The digest half is what makes this more than an exit-code table: a refusal
/// that exits 2 *after* writing would pass the status assertion alone.
#[test]
fn every_refusal_exits_non_zero_and_writes_nothing() {
    let fixture = Fixture::new(false);
    let project = fixture.project.to_str().unwrap().to_owned();
    let root = fixture.temp.path().join("refusal-vault");
    fixture.success(&[
        "init",
        "--root",
        root.to_str().unwrap(),
        "--profile",
        "default",
    ]);

    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("unknown host", vec!["init", "--yes", "--host", "nonesuch"]),
        (
            "unknown scope",
            vec!["init", "--yes", "--host", "claude-code", "--scope", "nope"],
        ),
        (
            "adopt with create",
            vec!["init", "--yes", "--adopt", "--create"],
        ),
        (
            "opencode version on claude",
            vec![
                "init",
                "--yes",
                "--host",
                "claude-code",
                "--opencode-version",
                "beta",
            ],
        ),
        ("teardown without a host", vec!["teardown", "--yes"]),
        (
            "cursor has no skill",
            vec![
                "instructions",
                "install",
                "skill",
                "--host",
                "cursor",
                "--project",
                &project,
            ],
        ),
        (
            "skill without a host",
            vec!["instructions", "install", "skill", "--project", &project],
        ),
        ("unknown subcommand", vec!["frobnicate"]),
        (
            "unknown flag",
            vec!["init", "--yes", "--host", "claude-code", "--wat"],
        ),
        (
            "profile show with junk",
            vec!["profile", "show", "default", "--yes"],
        ),
        (
            "disconnect with a profile",
            vec!["disconnect", "claude-code", "--profile", "default"],
        ),
        ("connect to nothing", vec!["connect"]),
        (
            "bad instruction target",
            vec!["instructions", "install", "nonesuch"],
        ),
        (
            "instructions with no target",
            vec!["instructions", "install"],
        ),
        (
            "logout both ways",
            vec!["logout", "--all-devices", "--local-only"],
        ),
    ];
    for (name, arguments) in cases {
        let before = fixture.tree_digest();
        let output = fixture.command(&arguments);
        assert_ne!(output.status.code(), Some(0), "{name} exited 0");
        assert!(
            !output.stderr.is_empty(),
            "{name} refused without saying anything"
        );
        assert_eq!(fixture.tree_digest(), before, "{name} wrote something");
    }
}

/// The one place the non-zero rule must NOT be applied.
///
/// A hook that exits non-zero is a hook the user turns off. The stdout
/// assertion is the second half: a hook that exits 0 having printed nothing
/// would satisfy the exit code and be useless.
#[test]
fn hook_session_start_always_exits_zero_and_says_something() {
    let fixture = Fixture::new(false);
    let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
    let output = command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .args([
            "--engine",
            "/nonexistent/kscope",
            "hook",
            "session-start",
            "--profile",
            "default",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "the hook must never fail");
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("the hook prints JSON");
    assert!(
        parsed["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|context| !context.is_empty()),
        "the hook exited 0 having said nothing"
    );
}

/// `init` with no `--host` stays rc=0 and SAYS it wired nothing.
///
/// "I ran init and nothing got wired" is the shape of a silent failure. Both
/// channels are asserted: the human line on stderr and the machine-readable
/// step, because a script never reads the first and a person never reads the
/// second.
#[test]
fn init_without_a_host_warns_that_nothing_was_wired() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("profile-only-vault");
    let output = fixture.command(&["init", "--yes", "--root", root.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Nothing was wired"), "{stderr}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let skipped = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step["step"] == "hosts" && step["status"] == "skipped");
    assert!(skipped, "the report must carry the skip: {report}");
}

/// USER SCOPE IS THE DEFAULT, and the split is reported.
///
/// All four placements are asserted, so a half-migrated implementation -- the
/// entry moved but not the hook, say -- fails rather than passing on the one
/// it did move.
#[test]
fn the_default_scope_is_user_and_the_split_is_reported() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("default-scope-vault");
    let output = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scope"], "user");
    assert_eq!(report["scope_source"], "default");
    assert_eq!(report["instructions_scope"], "project");
    assert_eq!(
        report["scope_applies_to"],
        serde_json::json!(["connect", "hook"])
    );

    // Connect and hook under the home; instructions and the skill in the
    // project. Every one of the four.
    assert!(
        fixture.home.join(".claude.json").is_file(),
        "the MCP entry did not move to the home"
    );
    assert!(
        fixture.home.join(".claude/settings.json").is_file(),
        "the hook did not move to the home"
    );
    assert!(
        !fixture.project.join(".mcp.json").exists(),
        "a project entry was still written"
    );
    assert!(
        fixture.project.join("CLAUDE.md").is_file(),
        "instructions must stay in the project"
    );
    assert!(
        fixture
            .project
            .join(".claude/skills/use-kaleidoscope/SKILL.md")
            .is_file(),
        "the skill must stay in the project"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("scope user (default)"), "{stderr}");

    // And an explicit flag is reported as such, so a reader can tell a default
    // from a choice.
    let explicit = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    let report: Value = serde_json::from_slice(&explicit.stdout).unwrap();
    assert_eq!(report["scope"], "project");
    assert_eq!(report["scope_source"], "flag");
}

/// A project-scope install left by the old default is NAMED, never removed.
///
/// "still present" and "rc 0" together rule out both the destructive
/// implementation and the one that fails the command it is diagnosing.
#[test]
fn a_project_scope_install_is_warned_about_and_never_removed() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("carryover-vault");
    let project = fixture.project.to_str().unwrap().to_owned();
    fixture.success(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        &project,
    ]);
    let mcp_before = fs::read(fixture.project.join(".mcp.json")).unwrap();
    let settings_before = fs::read(fixture.project.join(".claude/settings.json")).unwrap();

    let output = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--project",
        &project,
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the probe must not fail the command"
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let warning = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["step"] == "project_scope_carryover")
        .expect("the stale project install must be named");
    assert_eq!(warning["status"], "warning");
    assert_eq!(
        warning["remedy"],
        "kaleidoscope teardown --host claude-code --scope project"
    );
    let next = report["next"].as_array().unwrap();
    assert!(
        next.iter().any(|value| value == &warning["remedy"]),
        "the remedy must reach `next`: {next:?}"
    );
    assert_eq!(
        fs::read(fixture.project.join(".mcp.json")).unwrap(),
        mcp_before
    );
    assert_eq!(
        fs::read(fixture.project.join(".claude/settings.json")).unwrap(),
        settings_before
    );
}

/// The probe must absorb an error it cannot act on.
///
/// `inspect_owned_connection` returns `Err` for an unmanaged project entry.
/// A diagnostic that can fail the command it diagnoses is removed by the first
/// person it annoys, so rc=0 is the assertion.
#[test]
fn the_carryover_probe_survives_an_unmanaged_project_entry() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("foreign-carryover-vault");
    fs::write(
        fixture.project.join(".mcp.json"),
        br#"{"mcpServers":{"kaleidoscope":{"command":"somewhere-else"}}}"#,
    )
    .unwrap();
    let output = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a foreign PROJECT entry is not in user scope's way: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `--project` short-circuits the engine entirely.
///
/// Proved by PRECEDENCE, not by outcome: the engine here cannot answer, so a
/// run that consulted it would fail.
#[test]
fn an_explicit_project_never_consults_the_engine_for_the_root() {
    let fixture = Fixture::new(false);
    let stub = fixture.temp.path().join("stub-kscope");
    fs::write(
        &stub,
        "#!/bin/sh\ncase \"$1\" in --version) echo 'kscope 0.1.0-test';; where) echo 'no' >&2; exit 2;; *) exit 64;; esac\n",
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
    let output = command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .args([
            "--engine",
            stub.to_str().unwrap(),
            "instructions",
            "install",
            "claude",
            "--yes",
            "--project",
            fixture.project.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "--project must not need the engine: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.project.join("CLAUDE.md").is_file());
}

/// The opposite arm, and it must be the opposite ANSWER.
///
/// Engine present but unable to report the root: REFUSE. Falling back to the
/// working directory here would silently reintroduce the very defect being
/// fixed, for exactly the users who have an engine and expect it to be used.
#[test]
fn an_engine_that_cannot_report_the_root_refuses_and_names_project() {
    let fixture = Fixture::new(false);
    let stub = fixture.temp.path().join("stub-kscope-2");
    fs::write(
        &stub,
        "#!/bin/sh\ncase \"$1\" in --version) echo 'kscope 0.1.0-test';; where) echo 'unrecognised argument' >&2; exit 2;; *) exit 64;; esac\n",
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
    let output = command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .current_dir(&fixture.project)
        .args([
            "--engine",
            stub.to_str().unwrap(),
            "instructions",
            "install",
            "claude",
            "--yes",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--project"), "{stderr}");
    assert!(
        !fixture.project.join("CLAUDE.md").exists(),
        "a refusal must write nothing"
    );
}

/// The engine is asked for the project ONCE per invocation.
///
/// A per-call-site resolution produces exactly the same paths and fails only
/// this: the log is the instrument, not the outcome.
#[test]
fn the_project_root_is_resolved_once_per_invocation() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("once-vault");
    fixture.success(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
    ]);
    let log = fs::read_to_string(&fixture.log).unwrap();
    let calls = log.matches("<where> <--root-only>").count();
    assert_eq!(
        calls, 1,
        "the engine was asked {calls} times for the project root"
    );
}

/// `KSCOPE_ROOT` cannot move where project-scoped files are written.
///
/// It is a CANARY in this fixture, so it is set on every invocation. The
/// assertion is on `project_source`, not merely on the resulting path: proving
/// the allowlist exclusion is doing work, rather than that the value happened
/// to be absent.
#[test]
fn kscope_root_cannot_move_the_project_directory() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("canary-vault");
    let output = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(report["project"]["source"], "environment");
    assert_eq!(
        report["project"]["directory"],
        Value::String(fixture.project.display().to_string())
    );
    assert!(fixture.project.join(".mcp.json").is_file());
}

/// Each harness's own configuration-directory override moves the USER-scope
/// target, and only that one.
#[test]
fn the_harness_config_directory_overrides_are_honoured() {
    for (variable, relative) in [
        ("CLAUDE_CONFIG_DIR", "elsewhere/.claude.json"),
        ("XDG_CONFIG_HOME", "elsewhere/opencode/opencode.json"),
        ("CODEX_HOME", "elsewhere/config.toml"),
    ] {
        let fixture = Fixture::new(false);
        let elsewhere = fixture.temp.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        // CANONICALISED. The temp root is reached through /var, a symlink to
        // /private/var, and the manager refuses a configuration directory with
        // a symlinked ancestor -- correctly. An uncanonicalised path here made
        // the test fail on the guard rather than on the behaviour.
        let elsewhere = fs::canonicalize(&elsewhere).unwrap();
        let host = match variable {
            "CLAUDE_CONFIG_DIR" => "claude-code",
            "XDG_CONFIG_HOME" => "opencode",
            _ => "codex",
        };
        let root = fixture.temp.path().join(format!("{host}-override-vault"));
        let output = fixture.command_with(
            &[(variable, elsewhere.as_path())],
            &[
                "init",
                "--yes",
                "--root",
                root.to_str().unwrap(),
                "--host",
                host,
                "--project",
                fixture.project.to_str().unwrap(),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{variable}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let moved = fs::canonicalize(fixture.temp.path())
            .unwrap()
            .join(relative);
        assert!(
            moved.is_file(),
            "{variable} did not move the target to {}",
            moved.display()
        );
    }
}

/// A failure in the second tree must not leave the first applied.
///
/// The home-side assertion is the entire point: without the pre-flight, user
/// scope wrote `~/.claude.json` and only then failed on the read-only project.
#[test]
fn the_preflight_prevents_a_partial_apply_across_two_trees() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("preflight-vault");
    fs::set_permissions(&fixture.project, fs::Permissions::from_mode(0o555)).unwrap();
    let output = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--project",
        fixture.project.to_str().unwrap(),
    ]);
    fs::set_permissions(&fixture.project, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !fixture.home.join(".claude.json").exists(),
        "the home side was applied before the project side failed"
    );
    assert!(
        !fixture.home.join(".claude/settings.json").exists(),
        "the hook was installed before the project side failed"
    );
    assert!(!fixture.project.join(".mcp.json").exists());
}

/// Every removal reports which tier it achieved.
///
/// A reversibility claim that cannot say which of the three it reached is a
/// claim nothing can check.
#[test]
fn every_removal_reports_a_restore_tier() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("tier-vault");
    let project = fixture.project.to_str().unwrap().to_owned();
    fixture.success(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        &project,
    ]);
    let output = fixture.success(&[
        "teardown",
        "--yes",
        "--host",
        "claude-code",
        "--scope",
        "project",
        "--project",
        &project,
    ]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    for step in report["steps"].as_array().unwrap() {
        if step["action"] == "remove" {
            assert!(
                step["restore"].is_string(),
                "a removal with no reported tier: {step}"
            );
        }
    }
}

/// PROJECT-SCOPED FILES LAND AT THE PROJECT ROOT, NOT THE WORKING DIRECTORY.
///
/// Driven with an engine that actually WALKS -- the fixture's default answers
/// with the working directory, which is exactly the old behaviour and so could
/// not distinguish a fix from a regression.
///
/// The NEGATIVE half is what makes this non-vacuous: asserting only that the
/// four files exist at the root would pass for an implementation that wrote
/// them in BOTH places.
#[test]
fn a_nested_working_directory_writes_at_the_project_root() {
    let fixture = Fixture::new(false);
    fixture.make_the_engine_walk();
    let deep = fixture.project.join("src").join("deep");
    fs::create_dir_all(&deep).unwrap();
    fs::write(fixture.project.join("CLAUDE.md"), "# Mine\n").unwrap();

    let root = fixture.temp.path().join("nested-vault");
    let mut command = Command::new(env!("CARGO_BIN_EXE_kaleidoscope"));
    let output = command
        .env_clear()
        .env("HOME", &fixture.home)
        .env("KALEIDOSCOPE_USER_HOME", &fixture.home)
        .env("KALEIDOSCOPE_CONFIG_HOME", &fixture.config_home)
        .env("KALEIDOSCOPE_DATA_HOME", &fixture.data_home)
        .env("KSCOPE_PROFILE_HOME", &fixture.profile_home)
        .current_dir(&deep)
        .args([
            "--engine",
            fixture.engine.to_str().unwrap(),
            "init",
            "--yes",
            "--root",
            root.to_str().unwrap(),
            "--host",
            "claude-code",
            "--scope",
            "project",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    for relative in [
        ".mcp.json",
        "CLAUDE.md",
        ".claude/settings.json",
        ".claude/skills/use-kaleidoscope/SKILL.md",
    ] {
        assert!(
            fixture.project.join(relative).is_file(),
            "{relative} did not land at the project root"
        );
        assert!(
            !deep.join(relative).exists(),
            "{relative} was ALSO written in the working directory"
        );
    }
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["project"]["differs_from_cwd"], true);
    assert_eq!(
        report["project"]["directory"],
        Value::String(fixture.project.display().to_string())
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("project root is") && stderr.contains("not the current directory"),
        "the user must be told where the files went: {stderr}"
    );
}

/// A receiptless, DIFFERING Codex marker block must refuse with a remedy that
/// is true and that a user can actually carry out.
///
/// This is the shape adoption did not cover. `plan_codex_install_at` only
/// adopts a block that is byte-identical; anything else used to fall into
/// `validate_current_ownership`'s `(None, Some(current))` catch-all and report
/// `InvalidOwnerReceipt`, whose text says to "delete the Kaleidoscope entry and
/// its `*.kaleidoscope-owner.json` receipt beside it by hand" -- naming a
/// receipt that in this state does not exist.
///
/// The loop is the reason this is a defect rather than a wording nit: the user
/// hand-edits inside the block, is told to delete the entry AND the receipt,
/// deletes the receipt, and gets the IDENTICAL message back, now naming a file
/// they have already removed. Following the remedy can never satisfy it,
/// because the blocker is the block and the message talks about the receipt.
///
/// The refusal itself is correct and must stay: the content differs, so
/// adoption must not take it. Only the remedy has to become reachable.
#[test]
fn a_receiptless_differing_codex_block_refuses_with_a_reachable_remedy() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("codex-block-vault");
    let project = fixture.project.to_str().unwrap().to_owned();
    fixture.success(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "codex",
        "--scope",
        "project",
        "--project",
        &project,
    ]);

    let config = fixture.project.join(".codex/config.toml");
    let receipt = fixture
        .project
        .join(".codex/config.toml.kaleidoscope-owner.json");
    assert!(receipt.is_file(), "the clean install must leave a receipt");

    // Step 1: hand-edit INSIDE the manager's own block.
    let edited = fs::read_to_string(&config)
        .unwrap()
        .replace("startup_timeout_sec = 10", "startup_timeout_sec = 25");
    fs::write(&config, &edited).unwrap();

    // Step 2: follow the old remedy -- delete the receipt.
    fs::remove_file(&receipt).unwrap();

    let output = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "codex",
        "--scope",
        "project",
        "--project",
        &project,
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a differing block must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The remedy must not name a receipt that is not there.
    assert!(
        !stderr.contains("receipt beside it by hand"),
        "the refusal still names a receipt the user has already deleted: {stderr}"
    );
    // It must name a flag that `init` actually parses, and the concrete edit.
    assert!(
        stderr.contains("--no-connect"),
        "the refusal names no way forward: {stderr}"
    );
    assert!(
        stderr.contains("kaleidoscope-manager"),
        "the refusal does not say which region to delete: {stderr}"
    );
    // Nothing may have been written.
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        edited,
        "a refused init changed the file"
    );
    assert!(!receipt.exists(), "a refused init wrote a receipt");

    // And the named way forward must actually work.
    let proceeds = fixture.command(&[
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "codex",
        "--scope",
        "project",
        "--project",
        &project,
        "--no-connect",
    ]);
    assert_eq!(
        proceeds.status.code(),
        Some(0),
        "the flag the refusal named did not proceed: {}",
        String::from_utf8_lossy(&proceeds.stderr)
    );
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        edited,
        "--no-connect touched the block it was told to leave alone"
    );
}

/// The same file, made byte-identical again, is ADOPTED rather than refused.
///
/// The companion to the test above: the refusal's closing sentence promises
/// this, so it is asserted rather than left as prose.
#[test]
fn a_receiptless_identical_codex_block_is_adopted_in_place() {
    let fixture = Fixture::new(false);
    let root = fixture.temp.path().join("codex-adopt-vault");
    let project = fixture.project.to_str().unwrap().to_owned();
    let arguments = [
        "init",
        "--yes",
        "--root",
        root.to_str().unwrap(),
        "--host",
        "codex",
        "--scope",
        "project",
        "--project",
        &project,
    ];
    fixture.success(&arguments);

    let config = fixture.project.join(".codex/config.toml");
    let receipt = fixture
        .project
        .join(".codex/config.toml.kaleidoscope-owner.json");
    let before = fs::read(&config).unwrap();
    fs::remove_file(&receipt).unwrap();

    let output = fixture.success(&arguments);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let connect = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["step"] == "connect")
        .expect("a connect step");
    assert_eq!(
        connect["action"], "adopt",
        "identical content was not adopted"
    );
    assert_eq!(
        fs::read(&config).unwrap(),
        before,
        "adoption rewrote the file it was supposed to leave alone"
    );
    assert!(receipt.is_file(), "adoption did not write the receipt");
}

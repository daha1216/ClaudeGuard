//! Pure guarded GUI/CLI agent definitions, fingerprint matching, and PID-reuse checks.

pub struct GuiAgentDef {
    pub id: &'static str,
    pub name: &'static str,
}

pub const GUI_AGENTS: &[GuiAgentDef] = &[
    GuiAgentDef {
        id: "claude",
        name: "Claude",
    },
    GuiAgentDef {
        id: "chatgpt",
        name: "ChatGPT",
    },
    GuiAgentDef {
        id: "antigravity",
        name: "反重力",
    },
    GuiAgentDef {
        id: "cursor",
        name: "Cursor",
    },
    GuiAgentDef {
        id: "windsurf",
        name: "Windsurf",
    },
    GuiAgentDef {
        id: "zed",
        name: "Zed",
    },
    GuiAgentDef {
        id: "trae",
        name: "Trae",
    },
];

pub const CLI_AGENTS: &[(&str, &str)] = &[
    ("claude-code", "Claude Code"),
    ("codex", "Codex CLI"),
    ("gemini", "Gemini CLI"),
    ("aider", "Aider CLI"),
];

pub fn agent_ids() -> Vec<&'static str> {
    GUI_AGENTS.iter().map(|a| a.id).collect()
}

pub fn gui_agent_name(id: &str) -> &str {
    GUI_AGENTS
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.name)
        .unwrap_or(id)
}

pub fn cli_agent_name(id: &str) -> &str {
    CLI_AGENTS
        .iter()
        .find(|a| a.0 == id)
        .map(|a| a.1)
        .unwrap_or(id)
}

fn is_uninstaller_exe(exe_name_l: &str) -> bool {
    exe_name_l.starts_with("uninstall")
        || exe_name_l.starts_with("unins")
        || exe_name_l.contains("uninstaller")
}

/// Returns true if `exe_name_l` is a known Windows SCM service binary shipped with guarded agents.
pub fn is_agent_scm_service_exe(exe_name_l: &str) -> bool {
    matches!(
        exe_name_l,
        "cowork-svc.exe"
            | "codex-windows-sandbox-service.exe"
            | "elevation_service.exe"
            | "elevated_tracing_service.exe"
    )
}

fn is_claude_cli_path_l(exe_path_l: &str) -> bool {
    exe_path_l.contains(r"\claude\claude-code\")
        || exe_path_l.contains(r"\.local\bin\claude")
        || exe_path_l.contains(r"@anthropic-ai\claude-code")
        || exe_path_l.contains("@anthropic-ai/claude-code")
        || exe_path_l.contains("claude-code-win32")
}

fn path_under_dir_l(exe_path_l: &str, dir_raw: &str) -> bool {
    let trimmed = dir_raw.trim().trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        let lowered = trimmed.to_lowercase();
        exe_path_l
            .strip_prefix(lowered.as_str())
            .is_some_and(|rest| rest.starts_with('\\') || rest.starts_with('/'))
    } else {
        exe_path_l
            .strip_prefix(trimmed)
            .is_some_and(|rest| rest.starts_with('\\') || rest.starts_with('/'))
    }
}

/// Pure GUI process fingerprint match (all strings expected lowercased).
pub fn gui_agent_matches(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    claude_dir_l: Option<&str>,
) -> bool {
    gui_agent_matches_with_dirs(id, exe_name_l, exe_path_l, claude_dir_l, &[])
}

/// Pure GUI process fingerprint match with explicit custom Antigravity install directories.
pub fn gui_agent_matches_with_dirs(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    claude_dir_l: Option<&str>,
    antigravity_dirs_l: &[String],
) -> bool {
    let claude_dirs: Vec<String> = claude_dir_l
        .map(|d| vec![d.to_string()])
        .unwrap_or_default();
    gui_agent_matches_with_all_dirs(
        id,
        exe_name_l,
        exe_path_l,
        &claude_dirs,
        &[],
        antigravity_dirs_l,
    )
}

/// Pure GUI process fingerprint match with explicit custom install directories across all GUI agents.
pub fn gui_agent_matches_with_all_dirs(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    claude_dirs_l: &[String],
    chatgpt_dirs_l: &[String],
    ag_dirs_l: &[String],
) -> bool {
    if is_uninstaller_exe(exe_name_l) {
        return false;
    }
    match id {
        "claude" => {
            if is_claude_cli_path_l(exe_path_l) {
                return false;
            }
            exe_name_l == "claude.exe"
                || exe_path_l.contains(r"\windowsapps\claude_")
                || exe_path_l.contains(r"\anthropicclaude\")
                || exe_path_l.contains(r"\programs\claude\")
                || claude_dirs_l
                    .iter()
                    .any(|dir| path_under_dir_l(exe_path_l, dir))
        }
        "chatgpt" => {
            exe_name_l == "chatgpt.exe"
                || exe_path_l.contains(r"\windowsapps\openai.codex_")
                || exe_path_l.contains(r"\windowsapps\openai.chatgpt")
                || exe_path_l.contains(r"\programs\chatgpt\")
                || exe_path_l.contains(r"\programs\codex\")
                || chatgpt_dirs_l
                    .iter()
                    .any(|dir| path_under_dir_l(exe_path_l, dir))
        }
        "antigravity" => {
            exe_name_l == "antigravity.exe"
                || exe_name_l == "antigravity ide.exe"
                || exe_path_l.contains(r"\programs\antigravity\")
                || exe_path_l.contains(r"\programs\antigravity ide\")
                || ag_dirs_l
                    .iter()
                    .any(|dir| path_under_dir_l(exe_path_l, dir))
        }
        "cursor" => {
            exe_name_l == "cursor.exe"
                || exe_path_l.contains(r"\programs\cursor\")
                || exe_path_l.contains(r"\cursor\resources\app\")
        }
        "windsurf" => {
            exe_name_l == "windsurf.exe"
                || exe_path_l.contains(r"\programs\windsurf\")
                || exe_path_l.contains(r"\windsurf\resources\app\")
        }
        "zed" => {
            exe_name_l == "zed.exe"
                || exe_name_l == "zed-cli.exe"
                || exe_path_l.contains(r"\programs\zed\")
                || exe_path_l.contains(r"\apps\zed\")
        }
        "trae" => {
            exe_name_l == "trae.exe"
                || exe_path_l.contains(r"\programs\trae\")
                || exe_path_l.contains(r"\trae\resources\app\")
        }
        _ => false,
    }
}

/// Pure GUI process fingerprint match with explicit custom install directories for any agent id.
pub fn gui_agent_matches_with_custom_dirs(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    custom_dirs_l: &[String],
) -> bool {
    if is_uninstaller_exe(exe_name_l) {
        return false;
    }
    if id == "claude" && is_claude_cli_path_l(exe_path_l) {
        return false;
    }
    gui_agent_matches(id, exe_name_l, exe_path_l, None)
        || custom_dirs_l
            .iter()
            .any(|dir| path_under_dir_l(exe_path_l, dir))
}

/// Pure CLI process fingerprint match (CLI is warned/orphan-swept, or killed on trip when `kill_cli_on_fail` is enabled).
pub fn cli_agent_matches(id: &str, exe_name_l: &str, exe_path_l: &str, cmd_l: &str) -> bool {
    if is_uninstaller_exe(exe_name_l) {
        return false;
    }
    match id {
        "claude-code" => {
            cmd_l.contains(r"@anthropic-ai\claude-code")
                || cmd_l.contains("@anthropic-ai/claude-code")
                || exe_path_l.contains(r"\.local\bin\claude")
                || exe_path_l.contains(r"\claude\claude-code\")
                || exe_path_l.contains(r"@anthropic-ai\claude-code")
                || exe_path_l.contains("@anthropic-ai/claude-code")
                || exe_path_l.contains("claude-code-win32")
        }
        "codex" => {
            if exe_path_l.contains(r"\windowsapps\openai.")
                || exe_path_l.contains(r"\programs\codex\")
                || exe_path_l.contains(r"\programs\chatgpt\")
            {
                return false;
            }
            exe_name_l.starts_with("codex")
                || cmd_l.contains(r"@openai\codex")
                || cmd_l.contains("@openai/codex")
                || exe_path_l.contains(r"@openai\codex")
                || exe_path_l.contains("@openai/codex")
                || exe_path_l.contains("codex-win32-")
        }
        "gemini" => cmd_l.contains("gemini-cli"),
        "aider" => {
            exe_name_l == "aider.exe"
                || exe_name_l == "aider"
                || exe_path_l.contains(r"\aider\")
                || exe_path_l.contains(r"\aider-chat\")
                || exe_path_l.contains(r"\tools\aider-chat\")
                || cmd_l == "aider"
                || cmd_l.starts_with("aider ")
                || cmd_l.starts_with("aider.exe ")
                || cmd_l.contains("aider-chat")
                || cmd_l.contains("aider.main")
                || cmd_l.contains(" -m aider")
                || cmd_l.contains(r"\scripts\aider")
                || cmd_l.contains("/bin/aider")
        }
        _ => false,
    }
}

/// Confirms process identity across scan and termination to prevent PID-reuse collateral damage (T05-05).
pub fn same_process_identity(
    expected_start_time: u64,
    actual_start_time: u64,
    expected_path_l: &str,
    actual_path_l: &str,
) -> bool {
    expected_start_time != 0
        && expected_start_time == actual_start_time
        && !expected_path_l.is_empty()
        && expected_path_l == actual_path_l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_gui_agents_from_cli_and_validates_pid_identity() {
        assert!(gui_agent_matches(
            "claude",
            "claude.exe",
            r"c:\program files\windowsapps\claude_1.0\app\claude.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "claude",
            "claude.exe",
            r"c:\users\dev\.local\bin\claude.exe",
            None
        ));
        assert!(cli_agent_matches(
            "claude-code",
            "claude.exe",
            r"c:\users\dev\.local\bin\claude.exe",
            ""
        ));
        assert!(gui_agent_matches(
            "chatgpt",
            "chatgpt.exe",
            r"c:\program files\windowsapps\openai.codex_1.2\app\chatgpt.exe",
            None
        ));
        assert!(!cli_agent_matches(
            "codex",
            "codex-command-runner.exe",
            r"c:\program files\windowsapps\openai.codex_1.2\app\codex-command-runner.exe",
            ""
        ));
        assert!(same_process_identity(
            12345,
            12345,
            r"c:\app\claude.exe",
            r"c:\app\claude.exe"
        ));
        assert!(!same_process_identity(
            12345,
            99999,
            r"c:\app\claude.exe",
            r"c:\app\claude.exe"
        ));
    }

    #[test]
    fn antigravity_matches_install_tree_helpers_custom_dirs_and_excludes_uninstallers() {
        for (exe, path) in [
            (
                "antigravity.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\antigravity.exe",
            ),
            ("antigravity ide.exe", r"d:\portable\antigravity ide.exe"),
            (
                "language_server.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\resources\bin\language_server.exe",
            ),
            (
                "language_server_windows_x64.exe",
                r"c:\users\dev\appdata\local\programs\antigravity ide\resources\bin\language_server_windows_x64.exe",
            ),
            (
                "webm_encoder.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\resources\bin\webm_encoder.exe",
            ),
            (
                "elevate.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\resources\elevate.exe",
            ),
            (
                "agy.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\bin\agy.exe",
            ),
        ] {
            assert!(
                gui_agent_matches("antigravity", exe, path, None),
                "expected {exe} at {path} to match antigravity"
            );
        }

        for (exe, path) in [
            (
                "unins000.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\unins000.exe",
            ),
            (
                "uninstall antigravity.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\uninstall antigravity.exe",
            ),
            (
                "ag-uninstaller.exe",
                r"c:\users\dev\appdata\local\programs\antigravity\ag-uninstaller.exe",
            ),
            (
                "language_server.exe",
                r"c:\tools\other-lsp\bin\language_server.exe",
            ),
        ] {
            assert!(
                !gui_agent_matches("antigravity", exe, path, None),
                "expected {exe} at {path} NOT to match antigravity"
            );
        }

        let custom_dirs = vec![
            r"d:\custom\antigravity".to_string(),
            r"e:\ide\ag_root\".to_string(),
        ];
        assert!(gui_agent_matches_with_dirs(
            "antigravity",
            "language_server.exe",
            r"d:\custom\antigravity\resources\bin\language_server.exe",
            None,
            &custom_dirs,
        ));
        assert!(gui_agent_matches_with_dirs(
            "antigravity",
            "agy.exe",
            r"e:\ide\ag_root\bin\agy.exe",
            None,
            &custom_dirs,
        ));
        assert!(!gui_agent_matches_with_dirs(
            "antigravity",
            "language_server.exe",
            r"d:\custom\antigravity-other\resources\bin\language_server.exe",
            None,
            &custom_dirs,
        ));
        assert!(!gui_agent_matches_with_dirs(
            "antigravity",
            "unins000.exe",
            r"d:\custom\antigravity\unins000.exe",
            None,
            &custom_dirs,
        ));
    }

    #[test]
    fn matches_codex_desktop_helpers_claude_trees_scm_services_and_native_clis() {
        for (exe, path) in [
            (
                "codex.exe",
                r"c:\program files\windowsapps\openai.codex_26.501.0.0_x64__2p2nqsd0c76g0\app\codex.exe",
            ),
            (
                "codex.exe",
                r"c:\program files\windowsapps\openai.codex_26.501.0.0_x64__2p2nqsd0c76g0\app\resources\codex.exe",
            ),
            (
                "codex-code-mode-host.exe",
                r"c:\program files\windowsapps\openai.codex_26.501.0.0_x64__2p2nqsd0c76g0\app\codex-code-mode-host.exe",
            ),
            (
                "codex-command-runner.exe",
                r"c:\program files\windowsapps\openai.codex_26.501.0.0_x64__2p2nqsd0c76g0\app\codex-command-runner.exe",
            ),
            (
                "node.exe",
                r"c:\program files\windowsapps\openai.codex_26.501.0.0_x64__2p2nqsd0c76g0\app\resources\cua_node\bin\node.exe",
            ),
            (
                "codex-computer-use-helper.exe",
                r"c:\program files\windowsapps\openai.codex_26.501.0.0_x64__2p2nqsd0c76g0\app\codex-computer-use-helper.exe",
            ),
            (
                "chatgpt.exe",
                r"c:\program files\windowsapps\openai.chatgpt-desktop_1.2.0_x64\app\chatgpt.exe",
            ),
            (
                "codex.exe",
                r"c:\users\dev\appdata\local\programs\codex\codex.exe",
            ),
        ] {
            assert!(
                gui_agent_matches("chatgpt", exe, path, None),
                "expected {exe} at {path} to match chatgpt GUI"
            );
            assert!(
                !cli_agent_matches("codex", exe, path, "codex"),
                "expected desktop {exe} at {path} NOT to match codex CLI"
            );
        }

        // Custom dirs boundary check for all agents
        let claude_dirs = vec![r"d:\apps\claude".to_string()];
        let chatgpt_dirs = vec![r"d:\apps\codex_msix".to_string()];
        let ag_dirs = vec![r"d:\apps\ag".to_string()];
        assert!(gui_agent_matches_with_all_dirs(
            "claude",
            "electron.exe",
            r"d:\apps\claude\app\electron.exe",
            &claude_dirs,
            &chatgpt_dirs,
            &ag_dirs,
        ));
        assert!(!gui_agent_matches_with_all_dirs(
            "claude",
            "electron.exe",
            r"d:\apps\claude-other\app\electron.exe",
            &claude_dirs,
            &chatgpt_dirs,
            &ag_dirs,
        ));
        assert!(gui_agent_matches_with_all_dirs(
            "chatgpt",
            "node.exe",
            r"d:\apps\codex_msix\cua_node\bin\node.exe",
            &claude_dirs,
            &chatgpt_dirs,
            &ag_dirs,
        ));
        assert!(!gui_agent_matches_with_all_dirs(
            "chatgpt",
            "unins000.exe",
            r"d:\apps\codex_msix\unins000.exe",
            &claude_dirs,
            &chatgpt_dirs,
            &ag_dirs,
        ));

        // Claude desktop install trees vs CLI exclusion
        assert!(gui_agent_matches(
            "claude",
            "cowork-svc.exe",
            r"c:\users\dev\appdata\local\anthropicclaude\app-1.0\cowork-svc.exe",
            None
        ));
        assert!(gui_agent_matches(
            "claude",
            "helper.exe",
            r"c:\users\dev\appdata\local\programs\claude\helper.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "claude",
            "claude.exe",
            r"c:\users\dev\appdata\roaming\npm\node_modules\@anthropic-ai\claude-code-win32-x64\claude.exe",
            None
        ));

        // SCM service helper
        for svc in [
            "cowork-svc.exe",
            "codex-windows-sandbox-service.exe",
            "elevation_service.exe",
            "elevated_tracing_service.exe",
        ] {
            assert!(is_agent_scm_service_exe(svc));
        }
        assert!(!is_agent_scm_service_exe("claude.exe"));

        // Native CLIs
        assert!(cli_agent_matches(
            "claude-code",
            "node.exe",
            r"c:\program files\nodejs\node.exe",
            r"node c:/users/dev/npm/node_modules/@anthropic-ai/claude-code/cli.js"
        ));
        assert!(cli_agent_matches(
            "claude-code",
            "claude.exe",
            r"c:\users\dev\appdata\roaming\npm\node_modules\claude-code-win32-x64\claude.exe",
            ""
        ));
        assert!(cli_agent_matches(
            "codex",
            "node.exe",
            r"c:\program files\nodejs\node.exe",
            r"node c:/users/dev/npm/node_modules/@openai/codex/bin/codex.js"
        ));
        assert!(cli_agent_matches(
            "codex",
            "codex.exe",
            r"c:\users\dev\appdata\roaming\npm\node_modules\@openai\codex-win32-x64\codex.exe",
            ""
        ));
    }

    #[test]
    fn v5_seven_gui_and_four_cli_agents_match_accurately_and_exclude_uninstallers() {
        assert_eq!(agent_ids().as_slice(), &cg_protocol::KNOWN_GUI_AGENT_IDS);
        let cli_ids: Vec<&str> = CLI_AGENTS.iter().map(|(id, _)| *id).collect();
        assert_eq!(cli_ids.as_slice(), &cg_protocol::KNOWN_CLI_AGENT_IDS);

        // Cursor
        assert!(gui_agent_matches(
            "cursor",
            "cursor.exe",
            r"c:\users\dev\appdata\local\programs\cursor\cursor.exe",
            None
        ));
        assert!(gui_agent_matches(
            "cursor",
            "rg.exe",
            r"c:\users\dev\appdata\local\programs\cursor\resources\app\bin\rg.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "cursor",
            "unins000.exe",
            r"c:\users\dev\appdata\local\programs\cursor\unins000.exe",
            None
        ));

        // Windsurf
        assert!(gui_agent_matches(
            "windsurf",
            "windsurf.exe",
            r"c:\users\dev\appdata\local\programs\windsurf\windsurf.exe",
            None
        ));
        assert!(gui_agent_matches(
            "windsurf",
            "language_server_windows_x64.exe",
            r"c:\users\dev\appdata\local\programs\windsurf\resources\app\extensions\windsurf\bin\language_server_windows_x64.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "windsurf",
            "unins000.exe",
            r"c:\users\dev\appdata\local\programs\windsurf\unins000.exe",
            None
        ));

        // Zed
        assert!(gui_agent_matches(
            "zed",
            "zed.exe",
            r"c:\users\dev\appdata\local\programs\zed\zed.exe",
            None
        ));
        assert!(gui_agent_matches(
            "zed",
            "zed-cli.exe",
            r"c:\users\dev\scoop\apps\zed\current\zed-cli.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "zed",
            "uninstall.exe",
            r"c:\users\dev\appdata\local\programs\zed\uninstall.exe",
            None
        ));

        // Trae
        assert!(gui_agent_matches(
            "trae",
            "trae.exe",
            r"c:\users\dev\appdata\local\programs\trae\trae.exe",
            None
        ));
        assert!(gui_agent_matches(
            "trae",
            "marscode-helper.exe",
            r"c:\users\dev\appdata\local\programs\trae\resources\app\marscode-helper.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "trae",
            "unins000.exe",
            r"c:\users\dev\appdata\local\programs\trae\unins000.exe",
            None
        ));

        // Custom dirs helper
        let custom_trae = vec![r"d:\ides\trae".to_string()];
        assert!(gui_agent_matches_with_custom_dirs(
            "trae",
            "ai-agent.exe",
            r"d:\ides\trae\bin\ai-agent.exe",
            &custom_trae
        ));
        assert!(!gui_agent_matches_with_custom_dirs(
            "trae",
            "unins000.exe",
            r"d:\ides\trae\unins000.exe",
            &custom_trae
        ));

        // Aider CLI
        assert!(cli_agent_matches(
            "aider",
            "aider.exe",
            r"c:\users\dev\.local\bin\aider.exe",
            ""
        ));
        assert!(cli_agent_matches(
            "aider",
            "python.exe",
            r"c:\users\dev\appdata\roaming\uv\tools\aider-chat\scripts\python.exe",
            r"python -m aider --model claude-3-7-sonnet"
        ));
        assert!(cli_agent_matches(
            "aider",
            "python.exe",
            r"c:\python312\python.exe",
            r"python c:\users\dev\.local\pipx\venvs\aider-chat\scripts\aider"
        ));
        // Negative: never false-match unrelated binaries containing "raider"
        assert!(!cli_agent_matches(
            "aider",
            "tomb_raider.exe",
            r"d:\games\tomb_raider.exe",
            "tomb_raider.exe"
        ));
    }
}

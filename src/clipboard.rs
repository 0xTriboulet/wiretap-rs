use anyhow::{Result, anyhow};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClipboardCommand {
    program: &'static str,
    args: &'static [&'static str],
}

fn platform_commands() -> Vec<ClipboardCommand> {
    #[cfg(target_os = "macos")]
    {
        vec![ClipboardCommand {
            program: "pbcopy",
            args: &[],
        }]
    }
    #[cfg(target_os = "windows")]
    {
        vec![ClipboardCommand {
            program: "cmd",
            args: &["/C", "clip"],
        }]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            ClipboardCommand {
                program: "wl-copy",
                args: &[],
            },
            ClipboardCommand {
                program: "xclip",
                args: &["-selection", "clipboard"],
            },
            ClipboardCommand {
                program: "xsel",
                args: &["--clipboard", "--input"],
            },
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}

pub(crate) fn copy_to_clipboard(text: &str) -> Result<()> {
    copy_to_clipboard_with(text, run_command)
}

fn copy_to_clipboard_with<F>(text: &str, runner: F) -> Result<()>
where
    F: Fn(&ClipboardCommand, &str) -> Result<()>,
{
    let commands = platform_commands();
    if commands.is_empty() {
        return Err(anyhow!("clipboard is not supported on this platform"));
    }

    let mut last_err: Option<anyhow::Error> = None;
    for command in commands {
        match runner(&command, text) {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }

    Err(anyhow!(
        "clipboard command failed: {}",
        last_err.unwrap_or_else(|| anyhow!("unknown clipboard error"))
    ))
}

fn run_command(command: &ClipboardCommand, text: &str) -> Result<()> {
    let mut child = Command::new(command.program)
        .args(command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| anyhow!("{}: {}", command.program, err))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        Err(anyhow!("{}: clipboard command failed", command.program))
    } else {
        Err(anyhow!("{}: {}", command.program, stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn clipboard_tries_until_success() {
        let commands = platform_commands();
        if commands.len() < 2 {
            return;
        }

        let seen = RefCell::new(Vec::new());
        let result = copy_to_clipboard_with("hello", |command, _| {
            seen.borrow_mut().push(command.program);
            if seen.borrow().len() == 1 {
                Err(anyhow!("{} failed", command.program))
            } else {
                Ok(())
            }
        });

        assert!(result.is_ok());
        let seen = seen.borrow();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], commands[0].program);
        assert_eq!(seen[1], commands[1].program);
    }

    #[test]
    fn clipboard_reports_last_error() {
        let commands = platform_commands();
        if commands.is_empty() {
            return;
        }
        let last = commands.last().unwrap().program;
        let err = copy_to_clipboard_with("hello", |command, _| {
            Err(anyhow!("{} failed", command.program))
        })
        .expect_err("expected failure");
        let message = format!("{err}");
        assert!(message.contains(last));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clipboard_command_order_linux() {
        let commands = platform_commands();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].program, "wl-copy");
        assert_eq!(commands[1].program, "xclip");
        assert_eq!(commands[2].program, "xsel");
    }
}

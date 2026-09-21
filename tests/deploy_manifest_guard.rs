//! Deployment-artefact consistency guard.
//!
//! WHY THIS FILE EXISTS
//! --------------------
//! Commit 286c408 renamed the CLI binary from `wappalyzer` to `rustywap`
//! (Cargo.toml `[[bin]] name`). The Dockerfile was updated; the two Kubernetes
//! manifests under `deploy/k8s/` were not. They still said
//! `command: ["wappalyzer"]`, so every pod that rolled out died immediately
//! with:
//!
//!     exec: "wappalyzer": executable file not found in $PATH
//!
//! — a CrashLoopBackOff that nothing in the repo, the build, or CI could see.
//! `cargo build` was green, `cargo test` was green, `docker build` was green,
//! and the image ran fine locally with its own `CMD`; the manifests are plain
//! text that no tool in this project ever reads. The failure was only
//! discoverable by applying the manifest to a live cluster and watching pods
//! die, which is the most expensive place to find a typo.
//!
//! The manifests have since been corrected to `/usr/local/bin/rustywap`, but
//! that fix is a one-time edit, not a guarantee. The *next* rename of the
//! `[[bin]]` target, or a change to the Dockerfile's `COPY` destination, or a
//! new manifest copy-pasted from an old one, reintroduces the identical
//! CrashLoop by exactly the same route. This test is the guard that was
//! missing: it makes the four places that have to agree about the binary's
//! name and path agree *at `cargo test` time*, on a laptop and in CI, instead
//! of at deploy time in a cluster.
//!
//! The four sources of truth it reconciles:
//!
//!   1. `Cargo.toml`                      -> `[[bin]] name` (what cargo builds)
//!   2. `Dockerfile`                      -> `COPY` destination of the release
//!      binary, and the default `CMD`
//!   3. `deploy/k8s/wappalyzer.yaml`      -> `command[0]` (what kubelet execs)
//!   4. `deploy/k8s/wappalyzer.dev.yaml`  -> `command[0]`
//!
//! WHY PLAIN STRING MATCHING AND NOT A PARSER
//! ------------------------------------------
//! This crate has no YAML or TOML parsing dependency, and its dev-dependencies
//! are deliberately just `tokio-test` and `wiremock`. Adding `serde_yaml` or
//! `toml` for a lint-shaped test would mean a new entry in `Cargo.lock` (CI
//! builds with `--locked`, so a stale lock file fails the build outright) and a
//! new supply-chain dependency bought for one assertion. The hand-rolled
//! readers below are deliberately narrow: they understand the handful of forms
//! these specific files actually use, plus the obvious formatting variations
//! (single vs. double quotes, extra whitespace, trailing comments, YAML flow
//! sequences vs. block sequences), and they *fail loudly* on anything they do
//! not understand rather than quietly finding nothing.
//!
//! THE ONE RULE THIS FILE MUST NEVER BREAK
//! ---------------------------------------
//! A guard that passes when it cannot find what it is checking is worse than no
//! guard at all, because it reads as coverage. Every lookup below either finds
//! what it is looking for or panics with a message naming the file. "Not found"
//! is never treated as "fine".
//!
//! Files are located through `env!("CARGO_MANIFEST_DIR")` so the test behaves
//! identically regardless of the working directory the harness happens to use.

use std::fs;
use std::path::{Path, PathBuf};

/// Path of the build manifest, relative to the crate root.
const CARGO_TOML: &str = "Cargo.toml";

/// Path of the container build file, relative to the crate root.
const DOCKERFILE: &str = "Dockerfile";

/// Every Kubernetes manifest that execs the binary. Add new ones here: a
/// manifest that is not in this list is not guarded, and an unguarded manifest
/// is exactly how the original CrashLoop shipped.
const MANIFESTS: [&str; 2] = [
    "deploy/k8s/wappalyzer.yaml",
    "deploy/k8s/wappalyzer.dev.yaml",
];

// ── File access ──────────────────────────────────────────────────────────────

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Read a repo file, or fail with an explanation. A missing file is a failure,
/// never a skip: see "THE ONE RULE" above.
fn read_repo_file(relative: &str) -> String {
    let path = repo_path(relative);
    fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "deployment guard: could not read {} ({err}).\n\n\
             This test reconciles the binary name across Cargo.toml, the Dockerfile and the\n\
             Kubernetes manifests, so that a rename cannot silently reintroduce the\n\
             CrashLoopBackOff described at the top of tests/deploy_manifest_guard.rs.\n\
             It cannot do that with a file missing, and it refuses to pass without checking.\n\n\
             What to do:\n\
               * If the file was MOVED or RENAMED, update the path constants at the top of\n\
                 tests/deploy_manifest_guard.rs to match.\n\
               * If the file was DELETED on purpose, delete its entry from that list too.\n\
               * If the file exists in your working tree but not in a fresh clone or in CI,\n\
                 it is probably untracked: run `git status --porcelain deploy/` and\n\
                 `git add` it. An unshipped deployment fix protects nobody.",
            path.display()
        )
    })
}

// ── Small text helpers shared by the TOML / Dockerfile / YAML readers ────────

/// Drop a trailing `# ...` comment.
///
/// Quote-aware, and only treats `#` as a comment introducer at the start of the
/// text or after whitespace — which is the rule YAML uses, and is conservative
/// enough for TOML too. Without this, `command: ["/usr/local/bin/rustywap"]  # note`
/// would be read as a value ending in `# note`.
fn strip_inline_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut in_single = false;
    let mut in_double = false;

    for (idx, ch) in text.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => {
                // `idx - 1` may land mid-codepoint on a multi-byte character;
                // that byte is simply not ASCII whitespace, which is the answer
                // we want anyway.
                if idx == 0 || bytes[idx - 1].is_ascii_whitespace() {
                    return &text[..idx];
                }
            }
            _ => {}
        }
    }
    text
}

/// Strip one layer of matching `"` or `'` quotes, if present.
fn unquote(text: &str) -> &str {
    let text = text.trim();
    for quote in ['"', '\''] {
        if text.len() >= 2 && text.starts_with(quote) && text.ends_with(quote) {
            return &text[1..text.len() - 1];
        }
    }
    text
}

/// Last `/`-separated component of a path, i.e. the program name kubelet would
/// exec. `basename("/usr/local/bin/rustywap") == "rustywap"`.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Parse a bracketed list — a YAML flow sequence (`["a", "b"]`) or a Dockerfile
/// exec-form instruction (`["rustywap", "serve"]`), which are the same shape.
///
/// Returns `None` when `text` is not a complete single-line bracketed list, so
/// callers can report an unsupported form instead of silently seeing no items.
fn parse_bracketed_list(text: &str) -> Option<Vec<String>> {
    let text = text.trim();
    if !text.starts_with('[') || !text.ends_with(']') || text.len() < 2 {
        return None;
    }

    let inner = &text[1..text.len() - 1];
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut depth = 0usize;

    for ch in inner.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(ch);
            }
            '[' | '{' if !in_single && !in_double => {
                depth += 1;
                current.push(ch);
            }
            ']' | '}' if !in_single && !in_double => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if !in_single && !in_double && depth == 0 => {
                items.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        items.push(current);
    }

    Some(items.iter().map(|item| unquote(item).to_string()).collect())
}

// ── Cargo.toml: the [[bin]] name ─────────────────────────────────────────────

/// Collect every `name` declared under a `[[bin]]` table.
///
/// Tolerates comments, arbitrary spacing and either quote style. Section
/// headers are compared with whitespace removed so `[[ bin ]]` is recognised.
fn cargo_bin_names(toml: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_bin_table = false;

    for line in toml.lines() {
        let line = strip_inline_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_bin_table = line.replace(' ', "") == "[[bin]]";
            continue;
        }
        if !in_bin_table {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "name" {
                names.push(unquote(value).to_string());
            }
        }
    }
    names
}

/// The single binary name the whole deployment chain must agree on.
fn expected_bin_name() -> String {
    let toml = read_repo_file(CARGO_TOML);
    let names = cargo_bin_names(&toml);

    assert!(
        !names.is_empty(),
        "deployment guard: no `[[bin]]` section with a `name = \"...\"` key was found in {}.\n\
         Every other check in this test compares against that name, so without it the guard\n\
         would pass vacuously — which is how the `wappalyzer` -> `rustywap` rename produced a\n\
         cluster-wide CrashLoopBackOff unnoticed in the first place.\n\
         Restore the `[[bin]]` section, or update tests/deploy_manifest_guard.rs to read the\n\
         binary name from wherever it now lives.",
        repo_path(CARGO_TOML).display()
    );

    assert_eq!(
        names.len(),
        1,
        "deployment guard: {} declares {} `[[bin]]` targets ({}), and this guard does not know\n\
         which one the container image is supposed to run.\n\
         Teach it: replace `expected_bin_name()` in tests/deploy_manifest_guard.rs with the name\n\
         of the binary the Dockerfile installs and the Kubernetes manifests exec. Do not delete\n\
         the check — an unguarded manifest is how every pod ends up in CrashLoopBackOff.",
        repo_path(CARGO_TOML).display(),
        names.len(),
        names.join(", ")
    );

    names.into_iter().next().expect("length checked above")
}

// ── Dockerfile ───────────────────────────────────────────────────────────────

/// Split a Dockerfile into logical instructions, joining `\`-continued lines
/// and dropping whole-line comments. (Docker only honours `#` comments on a
/// line of their own, which is why this does not use `strip_inline_comment`.)
fn dockerfile_logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut accumulator = String::new();

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if accumulator.is_empty() && trimmed.is_empty() {
            continue;
        }
        match trimmed.strip_suffix('\\') {
            Some(head) => {
                accumulator.push_str(head.trim_end());
                accumulator.push(' ');
            }
            None => {
                accumulator.push_str(trimmed);
                out.push(accumulator.trim().to_string());
                accumulator.clear();
            }
        }
    }
    if !accumulator.trim().is_empty() {
        out.push(accumulator.trim().to_string());
    }
    out
}

/// Every `COPY` that installs a compiled artefact out of `target/release/`,
/// as `(source, resolved destination path)`.
///
/// A `COPY src dir/` destination is resolved to `dir/<source basename>` so the
/// comparison is always against a full file path, the way kubelet sees it.
fn dockerfile_release_binary_copies(text: &str) -> Vec<(String, String)> {
    let mut hits = Vec::new();

    for line in dockerfile_logical_lines(text) {
        let mut tokens = line.split_whitespace();
        let instruction = tokens.next().unwrap_or("");
        if !instruction.eq_ignore_ascii_case("COPY") {
            continue;
        }

        // Drop flags such as `--from=builder` / `--chown=...`.
        let args: Vec<&str> = tokens.filter(|t| !t.starts_with("--")).collect();
        if args.len() < 2 {
            continue;
        }
        let destination = unquote(args[args.len() - 1]);

        for source in &args[..args.len() - 1] {
            let source = unquote(source);
            if !source.contains("target/release/") {
                continue;
            }
            let resolved = if destination.ends_with('/') {
                format!("{destination}{}", basename(source))
            } else {
                destination.to_string()
            };
            hits.push((source.to_string(), resolved));
        }
    }
    hits
}

/// The argv of the last `CMD` or `ENTRYPOINT` instruction, exec form or shell
/// form. Returns `None` when the instruction is absent.
fn dockerfile_instruction_argv(text: &str, instruction_name: &str) -> Option<Vec<String>> {
    let mut found = None;

    for line in dockerfile_logical_lines(text) {
        let mut parts = line.splitn(2, char::is_whitespace);
        let instruction = parts.next().unwrap_or("");
        if !instruction.eq_ignore_ascii_case(instruction_name) {
            continue;
        }
        let rest = parts.next().unwrap_or("").trim();

        let argv = if rest.starts_with('[') {
            parse_bracketed_list(rest).unwrap_or_else(|| {
                panic!(
                    "deployment guard: the `{instruction_name}` instruction in {} looks like an\n\
                     exec-form list but this guard could not parse it as one:\n    {rest}\n\
                     Put the list on a single line, or extend `parse_bracketed_list()` in\n\
                     tests/deploy_manifest_guard.rs to handle the new form. Do not leave it\n\
                     unparsed: an unchecked default command is a pod that CrashLoops.",
                    repo_path(DOCKERFILE).display()
                )
            })
        } else {
            rest.split_whitespace().map(str::to_string).collect()
        };

        // Docker honours the last occurrence, so keep overwriting.
        found = Some(argv);
    }
    found
}

// ── Kubernetes manifests ─────────────────────────────────────────────────────

/// One `command:` found in a manifest, with the 1-based line number so failure
/// messages can point straight at it.
struct FoundCommand {
    line_no: usize,
    argv: Vec<String>,
}

/// Find every container `command:` in a manifest.
///
/// Handles the flow form (`command: ["/usr/local/bin/rustywap", "serve"]`), the
/// block form (`command:` followed by `- /usr/local/bin/rustywap` lines), a bare
/// scalar, a `command:` that opens a list item (`- command: ...`), either quote
/// style, and trailing comments. Comment lines are skipped, which matters here:
/// both manifests carry long prose comments that mention the word `command`.
fn manifest_commands(text: &str, relative_path: &str) -> Vec<FoundCommand> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();

    for (idx, raw) in lines.iter().enumerate() {
        let mut trimmed = raw.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        // `- command: [...]` — the key opening a sequence item.
        if let Some(rest) = trimmed.strip_prefix("- ") {
            trimmed = rest.trim_start();
        }
        let Some(rest) = trimmed.strip_prefix("command:") else {
            continue;
        };
        // Guard against keys like `commandLine:`; YAML requires whitespace (or
        // end of line) after the colon of a mapping key anyway.
        if !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
            continue;
        }

        let value = strip_inline_comment(rest).trim();
        let argv = if value.is_empty() {
            // Block sequence: consume the following `- item` lines.
            let mut items = Vec::new();
            for next in lines.iter().skip(idx + 1) {
                let next = next.trim();
                if next.is_empty() {
                    break;
                }
                if next.starts_with('#') {
                    continue;
                }
                let Some(item) = next.strip_prefix('-') else {
                    break;
                };
                items.push(unquote(strip_inline_comment(item).trim()).to_string());
            }
            items
        } else if value.starts_with('[') {
            parse_bracketed_list(value).unwrap_or_else(|| {
                panic!(
                    "deployment guard: {}:{} has a `command:` that looks like a flow sequence but\n\
                     this guard could not parse it as one:\n    {value}\n\
                     Put the list on a single line, or extend `parse_bracketed_list()` in\n\
                     tests/deploy_manifest_guard.rs. Leaving it unchecked means the next binary\n\
                     rename puts every pod into CrashLoopBackOff with nothing to catch it.",
                    relative_path,
                    idx + 1
                )
            })
        } else {
            vec![unquote(value).to_string()]
        };

        out.push(FoundCommand {
            line_no: idx + 1,
            argv,
        });
    }
    out
}

/// The single container `command:` of a manifest, or a loud failure.
fn manifest_command(relative_path: &str) -> FoundCommand {
    let text = read_repo_file(relative_path);
    let mut commands = manifest_commands(&text, relative_path);

    assert!(
        !commands.is_empty(),
        "deployment guard: no container `command:` found in {}.\n\
         The image declares `CMD [\"...\", \"serve\"]` and NO `ENTRYPOINT`. Kubernetes resolves\n\
         `command` and `args` independently — `command` replaces the image ENTRYPOINT and `args`\n\
         replaces the image CMD — so a manifest that sets only `args` inherits no program name at\n\
         all: kubelet would try to exec the first arg (`serve`) and the pod would CrashLoop.\n\
         Restore an explicit `command: [\"/usr/local/bin/<bin>\"]`, and keep `args` for the rest.",
        repo_path(relative_path).display()
    );

    assert_eq!(
        commands.len(),
        1,
        "deployment guard: {} contains {} `command:` keys (lines {}), and this guard cannot tell\n\
         which one belongs to the application container.\n\
         If an initContainer or sidecar was added, update `manifest_command()` in\n\
         tests/deploy_manifest_guard.rs to select the `wappalyzer` container specifically.\n\
         Do not delete the check: it is the only thing standing between a binary rename and a\n\
         cluster-wide CrashLoopBackOff.",
        repo_path(relative_path).display(),
        commands.len(),
        commands
            .iter()
            .map(|c| c.line_no.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let command = commands.remove(0);

    assert!(
        !command.argv.is_empty(),
        "deployment guard: {}:{} declares an EMPTY `command:` list.\n\
         kubelet has no program to exec, so the pod will fail to start. Set it to the absolute\n\
         path of the binary, e.g. `command: [\"/usr/local/bin/{}\"]`.",
        repo_path(relative_path).display(),
        command.line_no,
        expected_bin_name()
    );

    command
}

// ── The guards ───────────────────────────────────────────────────────────────

/// The original scar: manifest `command[0]` vs. the `[[bin]]` name cargo builds.
#[test]
fn k8s_command_matches_the_cargo_bin_name() {
    let bin_name = expected_bin_name();

    for relative_path in MANIFESTS {
        let command = manifest_command(relative_path);
        let program = &command.argv[0];

        assert_eq!(
            basename(program),
            bin_name,
            "\n\
             DEPLOYMENT MISMATCH — this WILL put every pod into CrashLoopBackOff.\n\n\
             {file}:{line} says:\n\
             \x20   command: [\"{program}\"]   (program name: \"{actual}\")\n\n\
             but {cargo} builds a binary named:\n\
             \x20   {expected}\n\n\
             kubelet execs `command[0]` verbatim inside the container. A name that does not exist\n\
             there fails as:\n\
             \x20   exec: \"{actual}\": executable file not found in $PATH\n\
             and the pod restarts forever. This exact failure shipped once already: commit 286c408\n\
             renamed the binary from `wappalyzer` to `rustywap` and both manifests kept the old\n\
             name, which nothing in the build, the tests or CI could see.\n\n\
             Fix one of the two, whichever is wrong:\n\
             \x20 * update {file} to `command: [\"/usr/local/bin/{expected}\"]`, or\n\
             \x20 * rename the `[[bin]]` target in {cargo} back to \"{actual}\"\n\
             and make sure the Dockerfile `COPY` destination agrees with both.",
            file = repo_path(relative_path).display(),
            line = command.line_no,
            program = program,
            actual = basename(program),
            expected = bin_name,
            cargo = repo_path(CARGO_TOML).display(),
        );
    }
}

/// The other half of the same scar: the manifests exec an absolute path, so the
/// Dockerfile has to actually put the binary at that path.
#[test]
fn dockerfile_installs_the_binary_where_the_manifests_exec_it() {
    let bin_name = expected_bin_name();
    let dockerfile = read_repo_file(DOCKERFILE);
    let copies = dockerfile_release_binary_copies(&dockerfile);

    assert!(
        !copies.is_empty(),
        "deployment guard: no `COPY ... target/release/... <dest>` instruction found in {}.\n\
         This guard reads that line to learn where the binary lands in the image, and compares it\n\
         with the absolute path the Kubernetes manifests exec. Without it the guard cannot check\n\
         anything, and a wrong path in a manifest is only discoverable as CrashLoopBackOff in a\n\
         live cluster.\n\
         If the build stage was restructured, update `dockerfile_release_binary_copies()` in\n\
         tests/deploy_manifest_guard.rs to match.",
        repo_path(DOCKERFILE).display()
    );

    assert_eq!(
        copies.len(),
        1,
        "deployment guard: {} copies {} artefacts out of target/release/ ({}), so this guard\n\
         cannot tell which one the manifests are meant to exec.\n\
         Update `dockerfile_release_binary_copies()` in tests/deploy_manifest_guard.rs to select\n\
         the service binary specifically.",
        repo_path(DOCKERFILE).display(),
        copies.len(),
        copies
            .iter()
            .map(|(src, dst)| format!("{src} -> {dst}"))
            .collect::<Vec<_>>()
            .join("; ")
    );

    let (source, installed_path) = &copies[0];

    // The COPY source is a build output, so this catches a rename that updated
    // Cargo.toml but not the Dockerfile. (That one at least fails `docker build`
    // loudly — but failing here, in `cargo test`, is cheaper and earlier.)
    assert_eq!(
        basename(source),
        bin_name,
        "\n\
         DEPLOYMENT MISMATCH — the image build will fail, or install the wrong binary.\n\n\
         {dockerfile} copies from:\n\
         \x20   {source}\n\
         but {cargo} builds `[[bin]] name = \"{expected}\"`, i.e. target/release/{expected}.\n\n\
         Update the COPY source (and its destination) to `{expected}`, or rename the `[[bin]]`\n\
         target back. These two names, plus `command[0]` in {manifests}, must always agree.",
        dockerfile = repo_path(DOCKERFILE).display(),
        source = source,
        cargo = repo_path(CARGO_TOML).display(),
        expected = bin_name,
        manifests = MANIFESTS.join(" and "),
    );

    assert_eq!(
        basename(installed_path),
        bin_name,
        "\n\
         DEPLOYMENT MISMATCH — this WILL put every pod into CrashLoopBackOff.\n\n\
         {dockerfile} installs the binary as:\n\
         \x20   {installed_path}   (file name: \"{actual}\")\n\
         but {cargo} builds `[[bin]] name = \"{expected}\"` and the manifests exec a path ending in\n\
         `/{expected}`.\n\n\
         The name kubelet execs is the name in the image, not the name cargo produced. Change the\n\
         COPY destination to end in `/{expected}`, or change every `command[0]` to match this path.",
        dockerfile = repo_path(DOCKERFILE).display(),
        installed_path = installed_path,
        actual = basename(installed_path),
        cargo = repo_path(CARGO_TOML).display(),
        expected = bin_name,
    );

    for relative_path in MANIFESTS {
        let command = manifest_command(relative_path);
        let program = &command.argv[0];

        // A bare program name (no `/`) is resolved through $PATH, which works
        // only as long as the install directory stays on PATH. The manifests
        // deliberately use the absolute path instead; when they do, it must be
        // the exact path the Dockerfile writes.
        if !program.contains('/') {
            continue;
        }

        assert_eq!(
            program,
            installed_path,
            "\n\
             DEPLOYMENT MISMATCH — this WILL put every pod into CrashLoopBackOff.\n\n\
             {file}:{line} execs the absolute path:\n\
             \x20   {program}\n\
             but {dockerfile} installs the binary at:\n\
             \x20   {installed_path}\n\n\
             kubelet execs `command[0]` verbatim; a path that does not exist in the image fails\n\
             with `exec: \"{program}\": stat {program}: no such file or directory` and the pod\n\
             restarts forever. Nothing outside this test compares these two strings.\n\n\
             Make them identical: either point the manifest at `{installed_path}`, or change the\n\
             Dockerfile COPY destination to `{program}`.",
            file = repo_path(relative_path).display(),
            line = command.line_no,
            program = program,
            dockerfile = repo_path(DOCKERFILE).display(),
            installed_path = installed_path,
        );
    }
}

/// The image's own default command must name the same binary. The Kubernetes
/// manifests override it, so this does not affect the cluster — it protects
/// `docker run` and anything else that starts the image without an override,
/// which would otherwise fail exactly the way the pods did.
#[test]
fn dockerfile_default_command_runs_the_same_binary() {
    let bin_name = expected_bin_name();
    let dockerfile = read_repo_file(DOCKERFILE);

    // With both present, CMD supplies arguments to ENTRYPOINT, so ENTRYPOINT[0]
    // is the program. With only CMD, CMD[0] is the program.
    let (instruction, argv) = match dockerfile_instruction_argv(&dockerfile, "ENTRYPOINT") {
        Some(argv) => ("ENTRYPOINT", argv),
        None => (
            "CMD",
            dockerfile_instruction_argv(&dockerfile, "CMD").unwrap_or_else(|| {
                panic!(
                    "deployment guard: {} declares neither CMD nor ENTRYPOINT, so the image has no\n\
                     default command and `docker run <image>` cannot start it.\n\
                     Restore `CMD [\"{bin_name}\", \"serve\"]` (the Kubernetes manifests override it\n\
                     with an explicit `command`, but nothing else does).",
                    repo_path(DOCKERFILE).display()
                )
            }),
        ),
    };

    assert!(
        !argv.is_empty(),
        "deployment guard: the `{instruction}` instruction in {} is empty, so the image has no\n\
         program to run. Set it to `[\"{bin_name}\", \"serve\"]`.",
        repo_path(DOCKERFILE).display()
    );

    assert_eq!(
        basename(&argv[0]),
        bin_name,
        "\n\
         DEPLOYMENT MISMATCH — `docker run` on this image will fail to start.\n\n\
         {dockerfile} sets:\n\
         \x20   {instruction} [\"{program}\", ...]   (program name: \"{actual}\")\n\
         but {cargo} builds `[[bin]] name = \"{expected}\"`, and that is the only binary the image\n\
         installs.\n\n\
         The container would die with `exec: \"{actual}\": executable file not found in $PATH` —\n\
         the same failure the Kubernetes manifests produced after commit 286c408 renamed the\n\
         binary. Update the {instruction} to `{expected}`.",
        dockerfile = repo_path(DOCKERFILE).display(),
        instruction = instruction,
        program = &argv[0],
        actual = basename(&argv[0]),
        cargo = repo_path(CARGO_TOML).display(),
        expected = bin_name,
    );
}

// ── Self-tests for the readers ───────────────────────────────────────────────
//
// The guards above are only as trustworthy as the hand-rolled readers they sit
// on. These cases pin the formatting variations the readers claim to tolerate,
// so that "the guard passed" cannot quietly mean "the reader found nothing".
// They are pure string parsing: no filesystem, no network.

#[test]
fn readers_tolerate_the_formatting_variations_they_claim_to() {
    // Cargo.toml: comments, spacing, both quote styles, and other tables that
    // must not be mistaken for `[[bin]]`.
    assert_eq!(
        cargo_bin_names(
            "[package]\nname = \"wappalyzer\"\n\n[[bin]]  # the service binary\nname='rustywap'\npath = \"src/main.rs\"\n\n[lib]\nname = \"rusty_wappalyzer\"\n"
        ),
        vec!["rustywap".to_string()],
        "the [[bin]] reader must ignore [package]/[lib] names and accept either quote style"
    );
    assert!(
        cargo_bin_names("[package]\nname = \"wappalyzer\"\n").is_empty(),
        "a manifest with no [[bin]] table must report none, so the guard fails loudly"
    );

    // YAML: flow form, block form, quotes, and prose comments that mention the
    // word `command` (both real manifests carry several).
    let flow = manifest_commands(
        "spec:\n  containers:\n    # container.command overrides the image ENTRYPOINT\n    - name: x\n      command: [\"/usr/local/bin/rustywap\", 'serve']  # absolute on purpose\n      args: [\"serve\"]\n",
        "<flow fixture>",
    );
    assert_eq!(flow.len(), 1, "comment lines mentioning `command` must not match");
    assert_eq!(
        flow[0].argv,
        vec!["/usr/local/bin/rustywap".to_string(), "serve".to_string()]
    );
    assert_eq!(flow[0].line_no, 5, "line numbers are 1-based and point at the key");

    let block = manifest_commands(
        "      command:\n        # why the absolute path\n        - /usr/local/bin/rustywap\n        - \"serve\"\n      args: []\n",
        "<block fixture>",
    );
    assert_eq!(block.len(), 1);
    assert_eq!(
        block[0].argv,
        vec!["/usr/local/bin/rustywap".to_string(), "serve".to_string()]
    );

    let scalar = manifest_commands("      command: rustywap\n", "<scalar fixture>");
    assert_eq!(scalar[0].argv, vec!["rustywap".to_string()]);

    assert!(
        manifest_commands("      args: [\"serve\"]\n      commandLine: nope\n", "<none>").is_empty(),
        "only a real `command:` key may match"
    );

    // Dockerfile: line continuations, whole-line comments, flag arguments and a
    // directory destination.
    let dockerfile = "# comment\nFROM rust AS builder\nRUN apt-get update \\\n    && apt-get install -y ca-certificates\nCOPY Cargo.toml Cargo.lock ./\nCOPY --from=builder /app/target/release/rustywap /usr/local/bin/\nCMD [\"rustywap\", \"serve\"]\n";
    assert_eq!(
        dockerfile_release_binary_copies(dockerfile),
        vec![(
            "/app/target/release/rustywap".to_string(),
            "/usr/local/bin/rustywap".to_string()
        )],
        "a directory destination must resolve to the full installed path"
    );
    assert_eq!(
        dockerfile_instruction_argv(dockerfile, "CMD"),
        Some(vec!["rustywap".to_string(), "serve".to_string()])
    );
    assert_eq!(dockerfile_instruction_argv(dockerfile, "ENTRYPOINT"), None);

    // Shared helpers.
    assert_eq!(strip_inline_comment("value  # note").trim(), "value");
    assert_eq!(strip_inline_comment("\"a#b\"  # note").trim(), "\"a#b\"");
    assert_eq!(basename("/usr/local/bin/rustywap"), "rustywap");
    assert_eq!(basename("rustywap"), "rustywap");
    assert_eq!(parse_bracketed_list("[\"a\", 'b']"), Some(vec!["a".to_string(), "b".to_string()]));
    assert_eq!(parse_bracketed_list("[\"a\","), None, "an unterminated list must be reported, not silently truncated");
}

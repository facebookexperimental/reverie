# Canonical skill packages

This is the canonical root for repository-wide Reverie product skills. Each
skill is a directory holding a `SKILL.md` and any package resources.
`.llms/skills` symlinks here, and `.agents/skills` holds one whole-package
symlink per skill, so Claude and stock Codex read the same bytes.

The roster is currently empty: the 2026-08-16 skills bankruptcy moved the
previous packages into `.skill_reset_20260816/skills/`, and they are being
regrown one at a time. To add one back, create `<name>/SKILL.md` here and
`../../.claude/skills/<name>` under `.agents/skills/`.

Run `scripts/check-skill-discovery.rs` after changing product skills. It
discovers whatever is here — there is no list to update.

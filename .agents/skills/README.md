# Codex skill entrypoints

Stock Codex discovers Reverie product skills here. Every entry is a
whole-package symlink to `.claude/skills/<name>/`; `.llms/skills` links to the
same canonical root. Claude, Codex, and `.llms` consumers therefore read the
same `SKILL.md` and package resources.

Run `scripts/check-skill-discovery.rs` after changing product skills.

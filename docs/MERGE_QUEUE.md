# Main branch landing

Pull requests into `main` require exact-head review and a fully green local
`./validate.sh` run. Local validation is the canonical landing signal. Hosted
GitHub Actions may provide additional information, but no hosted status context
is a landing requirement.

Land an approved, exact-head locally validated pull request with:

```bash
with-proxy gh pr merge <number> --repo rrnewton/REPOSITORY --merge
```

Replace `REPOSITORY` with `hermit` or `reverie`.

## Local validation

A full green `./validate.sh` run automatically creates and applies the
`locally-validated` label to the current branch's pull request. Set
`PR_NUMBER=<number>` when branch-based detection is unavailable. GitHub CLI,
authentication, proxy, missing-PR, and label-edit failures are warnings and do
not change validation's exit status.

Use `./validate.sh --no-label-pr` or `VALIDATE_LABEL_PR=0 ./validate.sh`
when a green run must not update GitHub.

The label records the canonical local validation, not a partial-test waiver.
Apply it only through a full green validator run on the exact pull request head.

## Repository settings

The `main` branch ruleset must:

1. require pull requests and linear history;
2. preserve the repository's review requirement;
3. require no hosted GitHub Actions status context; and
4. disallow force pushes and branch deletion.

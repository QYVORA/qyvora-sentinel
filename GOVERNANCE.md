# Governance

This document describes the governance model for the QYVORA Sentinel project.

## Principles

- **Transparency** — Decisions are made in the open via issues, discussions, and pull requests.
- **Meritocracy** — Contributors earn responsibility through sustained, quality contributions.
- **Community first** — Technical decisions prioritize the needs of users and the broader security community.
- **Stability** — Breaking changes follow a clear deprecation policy and release cadence.

## Roles

### User

Anyone who uses QYVORA Sentinel. Users can:

- Report bugs and request features via GitHub Issues
- Participate in discussions
- Submit feedback on roadmaps and proposals

### Contributor

Anyone who submits a pull request, files a well-formed issue, or provides documentation or community support. Contributors can:

- All User privileges
- Have their contributions reviewed and merged by maintainers
- Be listed in `AUTHORS.md`
- Participate in RFC discussions and vote on project direction

### Maintainer

Maintainers are trusted contributors with write access to the repository. They are responsible for:

- Reviewing and merging pull requests
- triaging issues and labeling them appropriately
- Guiding module development and architectural decisions
- Enforcing coding standards and quality gates
- Managing releases and versioning

Current maintainers are listed in `AUTHORS.md`.

## Decision Process

### Day-to-day decisions

Routine changes (bug fixes, documentation updates, new modules that follow existing patterns) are handled through the standard pull request process:

1. Contributor opens a PR against `main`.
2. At least one maintainer reviews and approves.
3. CI passes (lint, format, tests).
4. Maintainer merges via squash.

### Significant changes

Changes that affect the public API, module interface, CLI contract, or project architecture require:

1. An RFC (Request for Comments) issue or discussion thread.
2. At least 7 days of open discussion.
3. Approval from at least two maintainers.
4. A migration plan if the change is breaking.

### Release decisions

- Release timing is decided by maintainers.
- Release notes are curated from the changelog by the releasing maintainer.
- Any contributor may propose a release candidate by tagging an issue with `release-candidate`.

### Conflict resolution

If maintainers disagree on a technical direction:

1. The discussion is extended for additional community input.
2. If no consensus is reached, the project lead (or a designated maintainer) makes the final decision.
3. The rationale is documented in the relevant issue or RFC.

## Contribution Tiers

| Tier | Requirements | Privileges |
|------|-------------|------------|
| **Community** | Open a GitHub account, participate in issues/discussions | File issues, comment, suggest features |
| **Contributor** | Have at least one merged PR or equivalent contribution | Vote on RFCs, be listed in AUTHORS.md |
| **Trusted Contributor** | 5+ merged PRs, demonstrated expertise in an area | Review PRs (with maintainer approval), triage issues |
| **Maintainer** | Sustained contribution over 6+ months, nominated by existing maintainers | Write access, merge PRs, manage releases |

## Adding a Maintainer

1. An existing maintainer nominates a candidate via a private discussion among maintainers.
2. The nomination is announced in a public issue.
3. The community has 14 days to provide feedback.
4. If no objections are raised, the candidate is added as a maintainer with full repository access.

## Removing a Maintainer

A maintainer may step down voluntarily at any time. Inactive maintainers (no meaningful contribution in 6 months) will be asked if they wish to continue. If they do not respond within 30 days, their access is reduced to contributor level.

## Amendments

This governance document may be updated via the same RFC process described above. All changes require approval from at least two maintainers and a 14-day community comment period.

# Skill: build-feature

## Trigger

`/build-feature "Feature Name"`

## Description

Pipeline orchestrator that coordinates the multi-agent development workflow for a single feature from branch creation through final commit. Manages agent sequencing, retry loops, state persistence, and session resumption.

## Execution Steps

### 1. Branch Setup

- Sanitize the feature name to kebab-case (e.g., "User Authentication" -> `user-authentication`).
- Check if branch `feature/<name>` exists:
  - If yes: switch to it.
  - If no: create it from `main` and switch to it.

### 2. Check Pipeline State (Resume Support)

- Read `.claude/pipeline-state.md`.
- If an entry exists for this feature with status other than `COMPLETE`:
  - Log: "Resuming feature '<name>' from last completed step: <step>."
  - Skip to the next incomplete step.
- If no entry exists:
  - Create a new entry with status `STARTED`.

### 3. Run Agent 2 — Builder (TDD Development)

- Invoke the Builder agent (`.claude/agents/builder.md` or equivalent).
- The Builder follows TRUE TDD: write failing test first, then minimal code to pass, then refactor.
- The Builder reads `.claude/skills/rails-conventions/SKILL.md` for project conventions.
- The Builder reads `.claude/skills/security-knowledge/SKILL.md` to avoid known anti-patterns.
- The Builder reads `.claude/skills/aprs-domain-model/SKILL.md` for model reference.
- Update pipeline-state.md: `AGENT_2_COMPLETE`.

### 4. WIP Commit

- Stage all changes.
- Commit with message: `WIP: feat: <feature-name> - builder complete`.
- Update pipeline-state.md: `WIP_COMMIT_1`.

### 5. Run Agent 3 — Dependency Verifier (Anti-Hallucination Gate)

- Invoke the Dependency Verifier agent.
- Verifies that every gem, method, configuration option, and API used by Agent 2 actually exists.
- Checks `Gemfile.lock` versions against actual RubyGems releases.
- Validates Rails API calls against the project's Rails version (8.1).
- **On PASS:** Update pipeline-state.md: `AGENT_3_COMPLETE`.
- **On FAIL:**
  - Write feedback to `.claude/reviews/<feature>-dependency-verifier.md`.
  - Loop back to Agent 2 with the failure report.
  - Re-run Agent 3 after Agent 2 fixes.
  - Maximum 3 retries of the Agent 2 -> Agent 3 loop.
  - After 3 failures: halt pipeline and escalate to human review. Do NOT self-verify with relaxed constraints.
  - Update pipeline-state.md with failure count: `AGENT_3_RETRY_<n>`.

### 6. Run Agent 4 — Test Reviewer (Test Comprehensiveness)

- Invoke the Test Reviewer agent.
- Reviews test coverage for completeness: happy paths, edge cases, error cases, authorization, boundary conditions.
- **On PASS:** Update pipeline-state.md: `AGENT_4_COMPLETE`.
- **On GAPS:**
  - Write feedback to `.claude/reviews/<feature>-test-reviewer.md`.
  - Loop: Agent 2 (add missing tests) -> Agent 3 (verify) -> Agent 4 (re-review).
  - Maximum 2 retries of this loop.
  - Update pipeline-state.md: `AGENT_4_RETRY_<n>`.

### 7. Run Agent 5 — Code Reviewer (Security + Quality)

- Invoke the Code Reviewer agent.
- Reviews for security vulnerabilities (referencing `.claude/security-knowledge-base/`), code quality, Rails conventions, and CLAUDE.md compliance.
- Classifies findings as `CRITICAL`, `WARNING`, or `INFO`.
- **On PASS (no CRITICAL or WARNING):** Update pipeline-state.md: `AGENT_5_COMPLETE`.
- **On CRITICAL or WARNING:**
  - Write feedback to `.claude/reviews/<feature>-code-reviewer.md`.
  - Loop: Agent 2 (fix findings) -> Agent 3 (verify) -> Agent 5 (re-review).
  - Agent 4 is only re-run in this loop if the finding was test-related.
  - Maximum 1 retry of this loop.
  - Update pipeline-state.md: `AGENT_5_RETRY_<n>`.

### 8. Final Commit

- Stage all changes.
- Commit with a conventional commit message: `feat: <description of feature>`.
- The commit message must follow CLAUDE.md conventions (one logical change, conventional prefix).

### 9. Update Pipeline State

- Update pipeline-state.md: `COMPLETE`.
- Record completion timestamp.

## Re-Entry Rules

| Rejecting Agent | Fix Loop                           | Notes                                       |
|-----------------|------------------------------------|----------------------------------------------|
| Agent 3         | Agent 2 -> Agent 3                 | Max 3 retries, then escalate to human         |
| Agent 4         | Agent 2 -> Agent 3 -> Agent 4     | Max 2 retries                                |
| Agent 5         | Agent 2 -> Agent 3 -> Agent 5     | Max 1 retry; skip Agent 4 unless test-related|

- Agent 3 (Dependency Verifier) is **always** re-run after any Agent 2 fix, regardless of which agent originally rejected.
- Agent 4 is only re-run if Agent 4 was the original rejector.
- Agent 5 rejections skip Agent 4 re-run unless the specific finding was test-related.

## Iteration Cap

- Maximum **6 total iterations** across all retry loops per feature.
- If the cap is reached, the pipeline halts with status `HUMAN_REVIEW_REQUIRED`.
- Pipeline-state.md is updated with all accumulated feedback references.

## Pipeline State File Format

The file `.claude/pipeline-state.md` uses this format:

```markdown
# Pipeline State

## Feature: <feature-name>
- Branch: feature/<feature-name>
- Status: <status>
- Started: <ISO 8601 timestamp>
- Last Updated: <ISO 8601 timestamp>
- Iteration Count: <n>
- Current Step: <step description>
- Reviews:
  - .claude/reviews/<feature>-dependency-verifier.md
  - .claude/reviews/<feature>-test-reviewer.md
  - .claude/reviews/<feature>-code-reviewer.md
```

## Review File Format

Each review file in `.claude/reviews/<feature>-<agent>.md`:

```markdown
# <Agent Name> Review: <feature-name>

## Run <n> — <ISO 8601 timestamp>

### Status: PASS | FAIL

### Findings
- [CRITICAL|WARNING|SUGGESTION|GAP] <description>

### Required Actions
- <action item for Agent 2>
```

## Error Handling

- If `bundle exec rspec` fails during Agent 2, the failure output is captured and fed back to Agent 2 for correction before proceeding.
- If `bundle exec rubocop --parallel` reports offenses, Agent 2 must fix them before the WIP commit.
- If `bundle exec brakeman --no-pager` reports warnings, they are included in Agent 5's review context.
- If `bundle exec bundler-audit check` reports vulnerabilities, Agent 3 must flag them.

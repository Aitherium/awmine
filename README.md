# awmine

Turn the agent transcripts already on your disk into redacted rows of what failed, what you
corrected, what you repeat, and what it cost.

Every coding-agent session leaves a JSONL transcript behind, and those files already hold the
answers to four questions nobody re-reads them for: which tool calls fail and in what shape,
where the agent claimed "done" and you said otherwise, which step sequences you run again and
again, and what each session cost in tokens. awmine reads the transcripts as a stream, carries
the state that spans lines across runs, and emits one row file per question. Every string in
every row is redacted before it reaches disk; a row that fails redaction is a failed run, not a
warning.

Standard library only. No daemon. The wake is whatever scheduler you already have.

## Install

```bash
pip install awmine
```

Python 3.10 or newer. Linux, macOS and Windows. If `awtoll` is installed its transcript reader
and shape rules are reused; if not, a copy of the same idiom is used so the two never disagree
about what a step is called.

## Quick start

```bash
awmine run --since 7d              # mine new bytes since the last run (default roots: ~/.claude/projects)
awmine report                      # counts, cost per project, top lessons and procedures, redaction hits
awmine export --harvest            # exports/harvest.jsonl -- training-example rows
awmine export --codex --top 10     # exports/codex_candidates.yaml -- lesson candidates (reads a backlog, never writes it)
awmine export --teach              # exports/teach.jsonl -- {fork,state,answer,reward} rows
awmine export --skills             # exports/skills/<name>/SKILL.md drafts + toolpack_candidates.json
awmine share                       # OPT-IN: nothing leaves the box without --share or AWMINE_SHARE=1
awmine share --share               # render qualifying procedures as awskills/candidates/<slug>/SKILL.md
awmine --self-test                 # proves every extractor finds its planted case and that redaction can FAIL
```

Output root is `$AWMINE_OUT`, default `~/.aither/awmine/` (created `0700`). Roots come from
`--roots`, `$AWMINE_ROOTS`, `$AWTOLL_TRANSCRIPTS` or the default, in that order.

## What it emits

| file | one row per | what the row says |
|---|---|---|
| `outcomes.jsonl` | paired tool call | `{fork, state:{tool,args_shape,cwd_kind}, answer:"yes"|"no", reward:1.0, verdict, ...}` -- `yes` iff the call FAILED |
| `lessons.jsonl` | correction / interrupt / retry that worked | a claim, the human line that contradicted it, a marker score, quoted lines capped at 320 chars |
| `turns.jsonl` | ordinary next-task prompt after a claim | same row shape, kind `turn` -- kept apart so "lessons by kind" counts only real corrections |
| `procedures.jsonl` | maximal step window seen in >= 2 top-level sessions | normalized steps, `n_sessions`, `n_occurrences`, `n_subagent_occurrences`, `success_rate`, examples |
| `cost.jsonl` | session or subagent | tokens summed ONCE per API message id, tool-outcome ladder, API errors by status, last cost-state, awtoll's per-record delta |

Every row carries `ts` and `source: {root, path, line, session_id, top_session_id, ...}` where
`root` is `<HOME>`-substituted and `path` is relative to it. Three forked subagents of one run
map to their parent's `top_session_id`, so they count as ONE session for procedures and are
reported separately as subagent occurrences.

### Shapes, not arguments

A Bash step is the binary plus at most one subcommand token (`$ git push`, `$ pytest`,
`$ python -c (inline)`); any other tool is its name plus its input KEY names
(`Edit(file_path+new_string+old_string)`). Flags, paths, hosts, URLs, e-mails, branch names
and every other bare token are dropped, not placeholdered -- there is nothing to redact because
nothing was copied. The operator denylist is applied to every step afterwards as belt and braces.

### Redaction

One writer function redacts every string in every row (recursively) before bytes hit disk.
The vocabulary: generic key/token/secret patterns, GitHub/OpenAI/Anthropic/Google/HF/AWS key
shapes, JWTs, `Bearer` values, `X-API-Key`/`X-Internal-Key` headers, credential assignments,
private-key blocks, bare hex of 32+ characters, home directories (a Windows user-profile
prefix, `/home/...`, `/Users/...` become `<HOME>/`), e-mail addresses, and an **operator
denylist** of terms read from `$AWMINE_OUT/denylist.txt`, `$AWMINE_DENY` and `--deny` (case-insensitive, word-bounded,
each hit becomes `[REDACTED:name]`). The report prints the denylist term COUNT so an empty
denylist is visible.

A credential assignment is matched with the keyword as the **suffix of a longer identifier**,
because that is the shape a transcript is full of: `DB_PASSWORD=`, `PGPASSWORD=`,
`GITHUB_TOKEN=`, `AWS_SECRET_ACCESS_KEY=`, `export MY_API_KEY=`. The space-separated flag form
(`--password <value>`), `-u user:pass` and `scheme://user:pass@host` are covered too. The
right-hand boundary is the `=`/`:` itself, so `secretary=jane` and `http://host:8182/path` are
left alone.

Identifiers that are hex by construction (`content_hash`, `input_sha`, `error_key`, `id`,
`tool_use_id`, `session_id`, `promptId`, ...) are exempt from the secret patterns; the exemption
list is a module constant printed by `--self-test`, and the residual scan skips exactly those
fields and nothing else. An exception inside redaction aborts the run with exit 2 before that
file's rows or manifest entry are written.

### The leak check has two halves, and says which is which

- **Residual scan** -- re-apply the vocabulary to every file awmine wrote. Any hit is exit 1.
  This is a **self-consistency** check: it shares the vocabulary's blind spot by construction,
  so it can prove the writer redacted, never that the vocabulary was complete. The run summary
  says so on the line that prints it.
- **Vocabulary-free suspect scan** -- an entropy/shape heuristic that shares no pattern with the
  vocabulary, so a credential-shaped assignment under a keyword the vocabulary has never heard
  of is still named (by its NAME, never its value). It excludes the shapes measured as false
  positives on a real corpus -- a markdown code span, a UUID, a filename, a lowercase slug, an
  id range, an ISO date, a hex hash -- and those exclusions are module constants, not a list
  that grows per finding. A warning by default, because a heuristic over a whole corpus that
  floods gets switched off; `AWMINE_SUSPECTS_FATAL=1` makes it exit 1.

Both run over **every file under the output directory** -- rows, procedures, exports of any
format, `manifest.json` and the `steps/` cache -- not a hand-kept list of some of them. The
manifest carries quoted transcript text (the last claim, open tool errors) and is keyed by the
transcript's project directory, so it is redacted like anything else. The one file skipped is
the operator's own `denylist.txt`, which is input. A file awmine wrote that cannot be parsed is
exit 2, never a pass.

Changing the denylist after rows exist changes how paths are written in new rows; re-mine with
`--full` from an empty output dir when you add a term.

## Idempotency

`manifest.json` records, per `(root index, relative path)`, the byte offset and line count
reached plus a small `ResumeState` (pending call shapes, the last claim, open errors keyed by
input hash, an open interrupt) holding only shapes, hashes, line numbers and redacted capped
quotes. A re-run seeks to the offset and appends only rows from new lines; a call mined on one
run whose result lands on the next pairs normally. A file that shrank or was replaced re-mines
from 0 after its old rows are dropped from every row file (tmp + fsync + replace). Rows that a
crash left past the manifest's line count are dropped and re-appended once. The manifest is
replaced atomically only after a file's rows are on disk. `procedures.jsonl` and the report
are recomputed from the steps cache on every run.

Rows leave the miner **mid-file**, not at EOF: the buffer is flushed every `AWMINE_FLUSH_ROWS`
rows (default 4,000) so what is held does not track the size of the largest single transcript.
Rows may lead the manifest and never lag it, which is the same invariant crash repair already
relies on; if a transcript vanishes mid-read after a partial flush, its rows are rolled back to
the last durable line, because the manifest will never name that file for crash repair to plan
for.

The per-file `counts` block (conversation/sidecar/other/unreadable records and what was
skipped) **accumulates** across incremental mines, like its siblings `rows` and
`unreadable_lines`. A re-mine from 0 restarts the tally.

## Exports

- `--harvest` writes rows with the field names of a training-harvest example (messages capped
  at 2,000 characters, `content_hash` = md5 of the WRITTEN messages, `contains_private_prompts`
  true iff redaction hit that row).
- `--codex` writes lesson candidates in a `{id, source, title, origin, evidence, status, seen}`
  row shape whose evidence always carries `measured`, an ISO date and a line count. It reads a
  backlog file READ-ONLY (`--backlog`, or `$AWMINE_CODEX_BACKLOG`, or a project default found
  under the nearest repo root) to skip ids already present, emits at most `--top N` (default
  10) and reports `emitted / already_present / held_back`. It never writes the backlog.
- `--teach` writes `{fork, state, answer, reward}` rows. `--post` sends each as
  `{domain: "decide.awmine.tool_outcome", state: <json string>, answer, reward}` to
  `$AWRISE_DECIDE_URL/decide/outcome` with `$AWRISE_DECIDE_TOKEN` as a Bearer, 3 s timeout,
  any failure counted and never raised. Default is file only.
- `--skills` writes `exports/skills/<name>/SKILL.md` drafts (frontmatter `name` + `description`,
  numbered steps, measured counts; `--awskills-form` for the flat allowed-tools form) and
  `exports/toolpack_candidates.json` listing `awmine_proc_<slug>` functions. Drafts are capped at
  `--skills-top` (default 25, most sessions first) and the number held back is reported -- a real
  corpus yields tens of thousands of qualifying windows. Nothing is written outside `$AWMINE_OUT`.

## Share what qualified -- opt-in, gated, one PR

A mined procedure is not done when it is a row. It is done when it is a pack somebody else can
install. `awmine share` is that lane, and it is the one command that writes OUTSIDE `$AWMINE_OUT`,
so it is the one command that is off unless you ask for it.

```bash
awmine share                         # OFF: writes nothing, says so, exits 0
awmine share --share                 # this run only
AWMINE_SHARE=1 awmine share          # an unattended wake
awmine share --share --repo <checkout> --top 10
```

What a run does, in order:

1. **Selects** the procedures the miner's own signal gate already qualified (>= `--min-sessions`
   top-level sessions, default 2, most-repeated first, `--top` per run, default 10). A window of
   one step repeated is skipped -- a row file outlives the code that wrote it.
2. **Renders** each one to `awskills/candidates/<slug>/SKILL.md`: frontmatter `name` +
   `description`, the numbered steps, the measured counts, and the source `path:line` span of
   every example. The slug is a pure function of the procedure, so a re-run updates a candidate
   instead of creating a second one.
3. **Redacts again.** The rows were redacted when they were mined; the rendered text is redacted
   a second time here, and a candidate whose text still CHANGES under redaction is refused
   outright rather than quietly scrubbed -- a second hit means something got past the first pass.
4. **Asks the publish gate.** Every candidate is staged into a throwaway pack and put through
   `check_skills_publishable --offline` as a subprocess (`--gate`, `$AWMINE_PUBLISH_GATE`, or the
   checker found in the checkout). A candidate it rejects is not written. A finding that belongs
   to no candidate stops the whole run, and a gate that cannot answer is exit 2.
5. **Prints what you do next** -- add, commit, open ONE pull request -- and does none of it.
   awmine never commits, never pushes, never opens a PR and never touches the network here. The
   repository's existing skills-sync workflow is the publisher; a second lane is how mirrors
   drift.

`--repo` (or `$AWMINE_SHARE_REPO`) names the checkout that carries the pack; a named tree without
one is an error, never a reason to write somewhere you did not name. Exit 0 wrote (or opted out),
1 every candidate was refused, 2 there was nothing to judge with.

## Wake it

```bash
awrise add --name awmine-mine --every 6h --run "python -m awmine run --since 7d" --timeout 1800
awrise add --name awmine-share --every 24h \n  --run "python -m awmine run --since 7d && AWMINE_SHARE=1 python -m awmine share" --timeout 1800
```

Register it on the host that holds the transcripts. The wake never passes `--post`; teaching a
decision door stays a deliberate `awmine export --teach --post`.

## Exit codes

`0` clean · `1` a measured failure (a row failed redaction or validation, a residual hit,
a leak suspect under `AWMINE_SUSPECTS_FATAL=1`, a self-test check failed) · `2` could not judge
(no transcripts found, manifest unreadable, a written file unparsable, output dir unwritable,
redaction raised). Never 0 on silence.

Environment: `AWMINE_OUT` output dir · `AWMINE_DENY` extra denylist terms · `AWMINE_FLUSH_ROWS`
rows buffered before a mid-file flush · `AWMINE_SUSPECTS_FATAL=1` make the vocabulary-free
suspect scan a gate · `AWMINE_SHARE=1` opt in to the share lane · `AWMINE_SHARE_REPO`
the checkout to share into · `AWMINE_PUBLISH_GATE` the gate to run before writing.

### Self-test verifies

- `run_over_fixture_exits_0_with_0_residual_hits`
- `outcomes_denied_call_is_yes_and_retry_is_no`
- `outcomes_interrupted_call_is_unpaired_not_a_row`
- `outcomes_state_holds_only_tool_args_shape_cwd_kind`
- `bash_shape_drops_hostname_url_branch_email`
- `lessons_correction_interrupt_retry_worked_each_found`
- `correction_scores_at_least_one_whole_marker`
- `ordinary_next_task_lands_in_turns_not_lessons`
- `retry_worked_records_distance_and_count`
- `evidence_carries_measured_iso_date_and_line`
- `procedure_window_emitted_once_and_maximal`
- `three_forked_subagents_count_as_one_top_level_session`
- `success_rate_reflects_failing_occurrence`
- `no_bare_argument_survives_in_any_step`
- `cost_one_row_per_session_and_subagent_journals_excluded`
- `usage_counted_once_per_message_id_not_per_record`
- `api_error_counted_and_last_cost_state_kept`
- `awtoll_per_record_sum_exceeds_per_message_sum`
- `second_run_emits_zero_rows_and_identical_manifest_bytes`
- `split_call_across_runs_pairs_as_ok`
- `split_claim_across_runs_yields_correction`
- `remine_from_zero_leaves_row_counts_unchanged`
- `crash_between_flush_and_manifest_repaired_without_duplicates`
- `harvest_content_hash_is_md5_of_written_messages`
- `contains_private_prompts_true_on_every_redacted_row`
- `teach_rows_are_exactly_fork_state_answer_reward`
- `prefixed_credential_assignment_is_redacted` (`DB_PASSWORD=`, `--password <v>`, `-u user:pass`)
- `relaxing_that_anchor_does_not_redact_ordinary_text`
- `leak_sweep_opens_manifest_and_steps_cache_and_skips_the_denylist`
- `suspect_scan_names_a_shape_the_vocabulary_does_not_know`
- `suspect_scan_is_silent_on_awmines_own_output`
- `share_is_off_without_the_flag_and_writes_nothing`
- `share_renders_a_gated_candidate_with_its_marker_steps_and_source_spans`
- `share_slug_is_stable_across_runs`
- `share_refuses_a_secret_that_survived_into_a_row`
- `no_literal_canary_in_any_file_written` -- manifest and steps cache included; exits 1 under
  `AWMINE_SELFTEST_BREAK=redact` and `=denylist`

## Privacy limits, stated

Attachment payloads (hook stdout, prompt snapshots), raw tool inputs and whole transcripts are
never copied anywhere, including internal state. Lesson quotes are capped at 320 characters and
export message bodies at 2,000. Name detection beyond the e-mail pattern and the operator
denylist is not attempted; an undetected customer name inside a quoted line is the residual the
denylist exists to close.

## License

Apache-2.0.

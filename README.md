# awmine

<!-- aither-header:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

[Source](https://github.com/Aitherium/awmine)  ·  `pip install git+https://github.com/Aitherium/awmine.git`  ·  [The Aither World](https://aitherium.github.io/)

> **The Aither World** is an operating system for agents — a Linux you can hand to one, the runtimes it works in, and the tools it works with. [awnix](https://github.com/Aitherium/awnix) is the Linux underneath it; **awmine** is one of its 65 bricks — each installs on its own, runs offline, and needs no account.
>
> **Start here:** Point it at one transcript directory and read back what those sessions learned, with the line each lesson came from.

<!-- aither-header:end -->

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

<!-- aither-ecosystem:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

## The aw family

Standalone tools that share one idea: **replace something you would otherwise have to _trust_ with something you can _check_.**

Each installs on its own, works offline, and needs no account.

| | instead of trusting | you check |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | a framework's idea of how your agents should run | one loop you can read, pointed at a backend you already pay for |
| [awskills](https://github.com/Aitherium/awskills) | that an agent knows your procedure | the procedure written down, versioned, and loadable by any agent |
| [awpack](https://github.com/Aitherium/awpack) | that the pack you want shipped inside somebody's SDK, under whatever licence that SDK happens to carry | the pack as its own versioned artifact, with its own licence, that any agent runtime can install |
| [awm](https://github.com/Aitherium/awm) | that memory stayed in its lane | tenant:user:project scopes, so a write cannot cross a boundary |
| [awdesk](https://github.com/Aitherium/awdesk) | that the agent is somewhere behind a browser tab | a tray icon, a face on your desktop, and the decision card that pops when it needs you |
| [awnode](https://github.com/Aitherium/awnode) | a vendor's cloud with every prompt | a local gateway routing to backends you chose |
| [awgraph](https://github.com/Aitherium/awgraph) | that grep found everything | an AST + tree-sitter call graph an agent can traverse |
| [awgit](https://github.com/Aitherium/awgit) | that no one else is editing this file | a lease, refused at commit time if you do not hold it |
| [awdelphi](https://github.com/Aitherium/awdelphi) | one agent's confident take on a decision | the round trace, the anonymity, and who dissents |
| [awclassify](https://github.com/Aitherium/awclassify) | a filename, a folder, or whoever last touched it | doc_type, visibility, audience and topics, with the evidence lines that decided each |
| [awtoll](https://github.com/Aitherium/awtoll) | that your tooling is saving you context | the measured token cost of each tool call, and what the alternative cost |
| [awseal](https://github.com/Aitherium/awseal) | that the artifact came from who you think | an Ed25519 seal — the key that verifies is not the key that forges |
| [awshare](https://github.com/Aitherium/awshare) | that the download is intact | content-addressed bundles, verified on fetch |
| [awnest](https://github.com/Aitherium/awnest) | that there is a person on the other end | a verdict with evidence, where "we could not tell" is not "yes" |
| [awrena](https://github.com/Aitherium/awrena) | a leaderboard someone can edit, and votes nobody counted | a scored duel with both answers kept, and a result bound to them |
| [awnboard](https://github.com/Aitherium/awnboard) | a share link anyone who sees it can use | an invitation addressed to one person, for one gate, revocable |
| [awnix](https://github.com/Aitherium/awnix) | that the box is what you left it as | an immutable image you built, with atomic rollback |
| [awrecover](https://github.com/Aitherium/awrecover) | that the restore worked | a restore that fully lands or does not land at all |
| [awstorage](https://github.com/Aitherium/awstorage) | a du you ran last month, and a peers file that says 3 TB free | an inventory snapshot per node with a diff since the last one, and each tree classified re-fetchable or not |
| [awrelay](https://github.com/Aitherium/awrelay) | a SaaS in the middle of your agents | findings, alerts and coordination over your own transport |
| [awask](https://github.com/Aitherium/awask) | that anyone read the paragraph where you asked | the ask itself, with a button that steers the session that raised it |
| [awmail](https://github.com/Aitherium/awmail) | a mailbox somebody else can read | mail your agents send and receive over your own server |
| [awswarm](https://github.com/Aitherium/awswarm) | that a model either fits your GPU or it doesn't run at all | a placement plan and an acquisition-probability estimate before you spend on a run |
| [awfind](https://github.com/Aitherium/awfind) | one vendor's idea of the web | results from whichever providers you configured |
| [awbrowse](https://github.com/Aitherium/awbrowse) | that the page said what you were told | the render, the DOM and the requests it made |
| [awvoice](https://github.com/Aitherium/awvoice) | that a cloud vendor may hold your audio | a transcript and a wav from a service you host |
| [awvision](https://github.com/Aitherium/awvision) | a filename and a caption somebody wrote | what a model actually reports about the pixels |
| [awscreen](https://github.com/Aitherium/awscreen) | a selector that was true when the page was written | the elements actually rendered, by what they look like |
| [awbeads](https://github.com/Aitherium/awbeads) | that a layout your users built survives the next deploy | the arrangement as data you can read back, diff, and hand to another surface |
| [awbonsai](https://github.com/Aitherium/awbonsai) | that inference always means a request left the machine | a WebGPU model answering on the tab's own GPU, with a consent record logged before it ever loaded |
| [gawbbonet](https://github.com/Aitherium/gawbbonet) | the model to keep a 300-message campaign coherent by itself | campaign facts recalled from scoped memory you can list and edit |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | a vendor's quantisation defaults | sub-byte KV cache kernels you can benchmark yourself |
| [awrtifact](https://github.com/Aitherium/awrtifact) | a hand-rolled split script and a hand-edited worker manifest | byte-verified parts in a release, served with Range + CORS, sizes asserted by a live gate |
| [AitherZero](https://github.com/Aitherium/AitherZero) | a pile of scripts nobody has numbered | numbered, discoverable automation with declarative playbooks |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | what a page tells your browser to do | a federated search and desktop bridge you host |
| [awreason](https://github.com/Aitherium/awreason) | a confident paragraph | the phases it went through, and every tool call it made to get there |
| [awrecurse](https://github.com/Aitherium/awrecurse) | that everything you pasted in was actually read | which slices it opened, and what it concluded from each |
| [awprism](https://github.com/Aitherium/awprism) | the first explanation that fits | the ranked alternatives, and the observation that separates them |
| [awrepl](https://github.com/Aitherium/awrepl) | what the agent believes the value is | the value, printed from the live session |
| [awreport](https://github.com/Aitherium/awreport) | that the report you pasted carried no token in it | a redacted report, and the duplicate it merged into instead of filing twice |
| [awresearch](https://github.com/Aitherium/awresearch) | a summary of pages nobody opened | every claim against the source it came from |
| [awfocus](https://github.com/Aitherium/awfocus) | twelve terminal tabs and a bad memory | one command that names every session, finds any transcript, and opens or steers the one you want |
| [awgym](https://github.com/Aitherium/awgym) | that a world model learned anything from the games it saw | transitions captured from real play, fed back, and the retrodiction score falling on grids it never saw |
| [awpredict](https://github.com/Aitherium/awpredict) | a model because it trained without erroring | its prediction against a self-updating lookup, on the rows that are actually novel |
| [awevolve](https://github.com/Aitherium/awevolve) | that your optimisation loop is finding anything | every version it kept, the score that version earned, and the edit that produced it |
| [awsh](https://github.com/Aitherium/awsh) | that you already know the name of the command | what it decided your line meant, before it acts on it |
| **awmine** _(you are here)_ | that a session's lesson survived the session | a row per outcome, a candidate per lesson, and the transcript line each one came from |
| [awrise](https://github.com/Aitherium/awrise) | that a scheduled agent ran at all, and ran exactly once | a durable record of every wake -- fired, skipped, overlapped or timed out -- each with its reason |
| [awkno](https://github.com/Aitherium/awkno) | that the docs site is up, or that you remember the family | the whole ecosystem in your terminal, with no network at all |
| [awwall](https://github.com/Aitherium/awwall) | that a service only talks to the hosts you think it talks to | an explicit egress allowlist, where a denial names the rule that denied it |
| [awembed](https://github.com/Aitherium/awembed) | a general-purpose embedder that has never seen your code | a held-out split of whole directories, scored teacher vs student vs int8 |
| [awtax](https://github.com/Aitherium/awtax) | a closed tax app's sealed file you can never read again | a plain, provider-neutral schema of every figure, with the page it came from |
| [awsettings](https://github.com/Aitherium/awsettings) | that you will remember to re-approve the same thing on every box you work from | one profile, unioned rather than overwritten, with the credentials left behind |
| [awavatar](https://github.com/Aitherium/awavatar) | a cloud 3D vendor's opaque task id | a manifest with a sha256, a licence and a rig-audit verdict per file |

[**awnix**](https://github.com/Aitherium/awnix) is the ground floor — A Linux you can hand to an agent — immutable base, capabilities included.

## The Aitherium ecosystem

Every repository here is public. Each publishes an `aither-manifest.json` beside its page, so any surface can read every sibling's — the network is browsable from any node in it.

| repo | what it is | pages |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | Build AI agent fleets — 3 lines, any backend, local or cloud | [docs](https://aitherium.github.io/awdk/) |
| [awskills](https://github.com/Aitherium/awskills) | Portable agent skills — self-contained procedures an agent loads on demand | [docs](https://aitherium.github.io/awskills/) |
| [awpack](https://github.com/Aitherium/awpack) | First-party agent packs — the ones we build, versioned and installable on their own | [docs](https://aitherium.github.io/awpack/) |
| [awm](https://github.com/Aitherium/awm) | A portable, scoped agent memory | [docs](https://aitherium.github.io/awm/) |
| [awdesk](https://github.com/Aitherium/awdesk) | Aither World Desk -- the desktop body of AitherOS Online: tray, avatars, decision cards, the Living Desktop as an overlay | [docs](https://aitherium.github.io/awdesk/) |
| [awnode](https://github.com/Aitherium/awnode) | A lightweight local gateway — bridges your apps to the AI backends you chose | [docs](https://aitherium.github.io/awnode/) |
| [awrun](https://github.com/Aitherium/awrun) | A priority-aware queue and dispatcher for agentic runs and ad-hoc CI builds. It also judges whether the runner pool is big enough for the queue it is draining, and can ask a host to grow it -- reserving capacity is zero-sum, so a saturated pool needs more of it, not a different share of it | [docs](https://aitherium.github.io/awrun/) |
| [awgraph](https://github.com/Aitherium/awgraph) | A semantic code graph for agents — AST + tree-sitter, call graphs | [docs](https://aitherium.github.io/awgraph/) |
| [awgit](https://github.com/Aitherium/awgit) | Semantic version control on top of git — edit-ops and leases | [docs](https://aitherium.github.io/awgit/) |
| [awdelphi](https://github.com/Aitherium/awdelphi) | Anonymous multi-round expert panels — a converged answer with a trace | [docs](https://aitherium.github.io/awdelphi/) |
| [awclassify](https://github.com/Aitherium/awclassify) | Classify any document -- what it is, who may read it, who it is for, what it is about | — |
| [awtoll](https://github.com/Aitherium/awtoll) | What every tool call costs you in context, measured from your own transcripts | [docs](https://aitherium.github.io/awtoll/) |
| [awseal](https://github.com/Aitherium/awseal) | Sign an artifact so a stranger can verify it | [docs](https://aitherium.github.io/awseal/) |
| [awshare](https://github.com/Aitherium/awshare) | Publish an artifact and fetch it back verified | [docs](https://aitherium.github.io/awshare/) |
| [awdit](https://github.com/Aitherium/awdit) | An append-only audit trail whose gaps are DETECTABLE | [docs](https://aitherium.github.io/awdit/) |
| [awbac](https://github.com/Aitherium/awbac) | Role-based access control that fails closed and explains itself | [docs](https://aitherium.github.io/awbac/) |
| [awiam](https://github.com/Aitherium/awiam) | Who is this caller? A directory and session store that fails honestly | [docs](https://aitherium.github.io/awiam/) |
| [awtunnel](https://github.com/Aitherium/awtunnel) | Reach a service that has no public address | [docs](https://aitherium.github.io/awtunnel/) |
| [awnest](https://github.com/Aitherium/awnest) | Prove there is a human before you let them into the nest | [docs](https://aitherium.github.io/awnest/) |
| [awrena](https://github.com/Aitherium/awrena) | Put two agents head to head and get a verdict you can check | [docs](https://aitherium.github.io/awrena/) |
| [awnboard](https://github.com/Aitherium/awnboard) | A front gate you can put in front of anything, and hand someone the key to | [docs](https://aitherium.github.io/awnboard/) |
| [awnix](https://github.com/Aitherium/awnix) | A Linux you can hand to an agent — immutable base, capabilities included | [docs](https://aitherium.github.io/awnix/) |
| [awrecover](https://github.com/Aitherium/awrecover) | Labelled snapshots with an all-or-nothing restore | [docs](https://aitherium.github.io/awrecover/) |
| [awstorage](https://github.com/Aitherium/awstorage) | Every drive on every node, indexed, classified and diffed -- so you can see what you own before you delete it | [docs](https://aitherium.github.io/awstorage/) |
| [awrelay](https://github.com/Aitherium/awrelay) | Portable agent messaging — findings, alerts, coordination | [docs](https://aitherium.github.io/awrelay/) |
| [awask](https://github.com/Aitherium/awask) | Your agent asks you a question — and acts on your answer | [docs](https://aitherium.github.io/awask/) |
| [awmail](https://github.com/Aitherium/awmail) | Give an agent an email address — send, and actually receive | [docs](https://aitherium.github.io/awmail/) |
| [awnet](https://github.com/Aitherium/awnet) | The agentic web — agents host a mesh, and agents join one | [docs](https://aitherium.github.io/awnet/) |
| [awswarm](https://github.com/Aitherium/awswarm) | Run one model too big for any single GPU across a pool of small ones | — |
| [awfind](https://github.com/Aitherium/awfind) | A portable search client — query, results, ranking | [docs](https://aitherium.github.io/awfind/) |
| [awbrowse](https://github.com/Aitherium/awbrowse) | A portable browser client — navigate, console, network, DOM, screenshot | [docs](https://aitherium.github.io/awbrowse/) |
| [awvoice](https://github.com/Aitherium/awvoice) | Hear and speak — transcribe audio, synthesize a voice | [docs](https://aitherium.github.io/awvoice/) |
| [awvision](https://github.com/Aitherium/awvision) | See an image — describe it, ask it a question, compare two | [docs](https://aitherium.github.io/awvision/) |
| [awscreen](https://github.com/Aitherium/awscreen) | See this machine — what is on screen, and where to click it | [docs](https://aitherium.github.io/awscreen/) |
| [awkit](https://github.com/Aitherium/awkit) | Render an agent panel from a tool result — one component, any React app | — |
| [awbeads](https://github.com/Aitherium/awbeads) | A spatial canvas for a page — arrange things, connect them, and keep the arrangement | — |
| [awbonsai](https://github.com/Aitherium/awbonsai) | Run a real model in the visitor's own browser — no server round trip, no upload | — |
| [awknowledge](https://github.com/Aitherium/awknowledge) | How to run a coding agent so the result survives — the laws, with evidence | [docs](https://aitherium.github.io/awknowledge/) |
| [awbrain](https://github.com/Aitherium/awbrain) | Your history as a wiki of linked markdown — claims pinned to the evidence | — |
| [gawbbonet](https://github.com/Aitherium/gawbbonet) | GobboNet campaigns with a real agent brain — scoped memory, graph recall | [docs](https://aitherium.github.io/gawbbonet/) |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | Near-optimal KV cache quantization for LLM inference — sub-byte compression | [docs](https://aitherium.github.io/aitherkvcache/) |
| [awrtifact](https://github.com/Aitherium/awrtifact) | Deliberately chunk artifacts into GitHub release assets — the productized aitherkvcache mirror lane | [docs](https://aitherium.github.io/awrtifact/) |
| [AitherZero](https://github.com/Aitherium/AitherZero) | PowerShell 7+ automation framework — numbered, self-describing scripts | [docs](https://aitherium.github.io/AitherZero/) |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | Browser extension — federated AI search, page context, and the Living OS overlay | [docs](https://aitherium.github.io/AitherConnect/) |
| [awreason](https://github.com/Aitherium/awreason) | A portable reasoning client — sessions, phases, thoughts, and the chain that produced the answer | [docs](https://aitherium.github.io/awreason/) |
| [awrecurse](https://github.com/Aitherium/awrecurse) | Answer a question over a context far larger than the window — recursively, with the trace kept | [docs](https://aitherium.github.io/awrecurse/) |
| [awprism](https://github.com/Aitherium/awprism) | Turn a failure into ranked hypotheses — and say what would confirm each one | [docs](https://aitherium.github.io/awprism/) |
| [awrepl](https://github.com/Aitherium/awrepl) | A REPL an agent can actually use — state that survives between turns | [docs](https://aitherium.github.io/awrepl/) |
| [awreport](https://github.com/Aitherium/awreport) | File a bug report that has already scrubbed your secrets and collapsed the duplicate | — |
| [awresearch](https://github.com/Aitherium/awresearch) | Ask a research question, get a cited report you can check | [docs](https://aitherium.github.io/awresearch/) |
| [awfocus](https://github.com/Aitherium/awfocus) | See, search and steer every Claude session from one command | [docs](https://aitherium.github.io/awfocus/) |
| [awgym](https://github.com/Aitherium/awgym) | An ARC training gym — a game a world model can watch, and six roles that play through it | [docs](https://aitherium.github.io/awgym/) |
| [awpredict](https://github.com/Aitherium/awpredict) | Predict what your environment does next, and how surprised you were | [docs](https://aitherium.github.io/awpredict/) |
| [awevolve](https://github.com/Aitherium/awevolve) | Point an agent at a file and a command that scores it, and let it improve | — |
| [awsh](https://github.com/Aitherium/awsh) | Your terminal answers you -- type a question where a command would go | [docs](https://aitherium.github.io/awsh/) |
| **awmine** _(you are here)_ | Mine what your agents did -- outcomes, lessons and procedures out of the transcripts they left behind | — |
| [awrise](https://github.com/Aitherium/awrise) | Wake an agent on a schedule, let it do one thing, and put it back to sleep | [docs](https://aitherium.github.io/awrise/) |
| [awkno](https://github.com/Aitherium/awkno) | The man page for the Aither World — every brick, stack and law, offline | [docs](https://aitherium.github.io/awkno/) |
| [awwall](https://github.com/Aitherium/awwall) | Say what a workload may reach, and watch everything else fail closed | [docs](https://aitherium.github.io/awwall/) |
| [awrouter](https://github.com/Aitherium/awrouter) | OpenRouter for your own fleet: pick a model backend by cost/latency/ capability, fail over, fit the context window, stream. Standalone, OpenAI-compatible, no Aither-specifics required to be valuable | — |
| [awembed](https://github.com/Aitherium/awembed) | Train an embedding model that knows your corpus, and prove it beats the big one | [docs](https://aitherium.github.io/awembed/) |
| [awtax](https://github.com/Aitherium/awtax) | Turn any tax PDF -- returns, W-2, 1099, statements, even scans -- into structured data you can check | [docs](https://aitherium.github.io/awtax/) |
| [awflow](https://github.com/Aitherium/awflow) | A deterministic workflow runtime — chain agent calls with journal replay and budget control | [docs](https://aitherium.github.io/awflow/) |
| [awsettings](https://github.com/Aitherium/awsettings) | Your agent's permissions and config, following you to the next machine | [docs](https://aitherium.github.io/awsettings/) |
| [awavatar](https://github.com/Aitherium/awavatar) | One character spec in, a rigged, animated, multi-style avatar pack out | [docs](https://aitherium.github.io/awavatar/) |

<div id="aither-constellation" data-self="awmine"></div>
<script src="aither-constellation.js"></script>

<!-- aither-ecosystem:end -->

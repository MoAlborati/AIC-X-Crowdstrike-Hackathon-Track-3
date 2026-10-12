# Archetype: chat-responder

| | |
|---|---|
| **Purpose** | Answer human chat in GitHub Issues (CHAT.md): status questions, decisions, work requests. Chat is priority intake, so it is answered before other work. |
| **When to dispatch** | Normally the **orchestrator answers chat itself**, as the first thing on each tick. Dispatch a child only when an answer needs research (reading many files, running a command, measuring something) that would block the tick. |
| **Inputs** | The `CHAT_EVENT` line from `scripts/chat-poll.sh` (`prio=… issue=#N from=… key=…`), plus the issue thread (`gh issue view N --comments`). |
| **Read / write** | Read-only, except the reply comment. Work requests become tickets or child agents. The responder doesn't implement them. |
| **Output** | One comment on issue #N ending `<!-- orchestrator-reply -->`. For a long job, post a quick acknowledgement first and the result later in the same thread. |
| **Time box** | Acknowledge within about 1 minute. A researched answer gets 15 minutes. |
| **Ends** | `STATUS: DONE` with the comment URL. |

## Reply rules
- `chat-urgent` threads come first.
- Answer the question in the first line. Then give the evidence: PR or issue links, a command, or a number taken from a file on main.
- Never paste the marker in the middle of a human's quote. The marker goes once, at the end.
- If the human made a decision, append it to the STATE.md Decision Log on the next STATE refresh.
- **Close answered issues:** when a thread is resolved (question answered, decision applied, PR merged),
  close it with `gh issue close N --comment "<one line> <!-- orchestrator-reply -->"`. Keep the pinned #32 open.

## needs-human questions (decisions only a human can make)
Open a new issue:
- **Title** `[@owner by HH:MM PDT] <question>`.
- **Labels** `chat,needs-human` (add `chat-urgent` if the deadline is under an hour away).
- **Assign it to the same owner** (`--assignee <login>`). The `@owner` in the title must also be the assignee.
- **Body**: the question, the options, the **default** that will be applied, and the deadline.
- At **T-15 minutes**, re-ping: `@owner reminder: default "<X>" applies at HH:MM PDT`.
- **At the deadline**, apply the default, comment what was done, and close the issue (or keep it open if the default needs human action, as #106 did).

## Dispatch template (research answers only)
```
You are the CHAT-RESPONDER child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/chat-responder.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Answer issue #<N> (from @<login>): "<question>". Read-only. One comment ending <!-- orchestrator-reply -->.
End with the comment URL and STATUS.
```

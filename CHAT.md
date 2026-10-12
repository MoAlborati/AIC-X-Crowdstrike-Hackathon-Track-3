# CHAT — talk to the orchestrator through GitHub Issues

Operator direction: "create an intake/conversational channel ... through github issues".

The build orchestrator watches this repo's open issues and replies in them. Chat is a **priority async
intake** that runs in parallel with the build loop (`LOOP.md`). The orchestrator answers chat **before**
any other work, then goes back to the loop.

## Start a chat
- **New issue → "Chat with the orchestrator"**. This form adds the `chat` label. Write your message and submit.
- Or comment on any open issue. The pinned welcome issue **#32** is a fine place for quick questions.
- Blank issues still work. Any open issue is watched.
- Keep it public-safe: the repo goes public, so don't post secrets or private notes.

## What to ask
- **Status:** "Where is T3?", "What's blocking the demo?", "What did the last delivery gate show?"
- **Decisions:** "Why are response-side checks alert-only?", "Pick A or B for the pitch", or overrule a choice.
- **Work requests:** "Add X to the demo script", "Re-run the gate on PR #N", "Draft the pitch slide".
  The orchestrator turns a request into a ticket or a child agent and links the resulting PR in the thread.
  The endgame policies in `LOOP.md` still apply, so after the 14:30 feature freeze only demo-path fixes are accepted.

## Urgent
Add the **`chat-urgent`** label, or tick **Urgent?** in the chat form. Urgent threads are answered first.

## Response time
Usually **about 1 minute**. The poller checks every 15s, and a reply follows once the orchestrator finishes its
current step. A long-running request gets a quick acknowledgement first and the result later in the same thread.

## How the marker works
Every orchestrator reply contains the hidden HTML comment `<!-- orchestrator-reply -->`. It doesn't render on GitHub.
A thread counts as **answered** when its newest item (the issue body, or the last comment) has the marker.
When you post a new message, the thread becomes **unanswered** again and the orchestrator picks it up.
Humans shouldn't paste the marker, because the poller would then treat their message as already answered.

## Under the hood
`scripts/chat-poll.sh` polls open issues and prints one line per unanswered message:
```
CHAT_EVENT prio=URGENT|normal issue=#N from=<login> key=<issue:comment-id> title=<title>
```
- `CHAT_REPO=owner/repo` targets another repo. The default is this one.
- `CHAT_INTERVAL` sets the poll interval in seconds (default 15).
- Seen-message keys live in `.chat/`, which is gitignored.
- Issues and comments are fetched with `--paginate`, so no capped list scan drops a thread.
  A failed API call is logged to stderr, never skipped silently.

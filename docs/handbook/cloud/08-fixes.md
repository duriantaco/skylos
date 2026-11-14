# Fix pull requests and cleanup

Cloud can help fix an issue in three ways: a fix brief you act on yourself,
a pull request written by an AI model, and a small weekly pull request that
removes unused code.

| | Cost | Needs |
|:--|:--|:--|
| Fix brief | Free | Nothing |
| Automatic fix pull request | 3 credits each | Owner or admin, the Skylos GitHub App on the repository |
| Weekly cleanup pull request | 3 credits each | Owner or admin, the Skylos GitHub App on the repository |

None of them needs a paid plan. Credits work on Free too.

## Fix it yourself with a fix brief

**For:** a precise description of the problem that you, or your own AI
coding agent, can act on.

**Who:** any member.

1. Open an issue and select **Fix**.
2. Under **Fix it myself**, select **Show the fix brief**.
3. Select **Copy fix brief**, or copy it as a prompt for your AI coding
   agent.

![How do you want to fix this? The fix brief on the left, the AI fix pull request on the right.](img/cloud/fixes-dialog.png)

The brief says what is wrong, why it matters, how to fix it in the file's
language, what not to do, where the code is, and how the data flows. It
uses no credits.

![A fix brief for a SQL injection.](img/cloud/fixes-brief.png)

Push your fix and let CI upload again. The issue is fixed when the next
trusted scan of the default branch no longer finds it.

## Automatic fix pull requests

**For:** letting an AI model write the change and open the pull request.

**Who:** an owner or admin. The project must be connected through the
Skylos GitHub App and the scan must be tied to a full commit. Python,
JavaScript and TypeScript files only. Workflow files under
`.github/workflows` are never changed.

1. Open an issue and select **Fix**.
2. Under **Let AI fix it (OpenAI)**, select **Create fix PR · 3 credits**.
3. Confirm.

**What it does**

- It sends the one file (up to 64 KiB) to OpenAI with the finding.
- If the branch already has an open pull request, Skylos posts the fix as a
  suggestion on it. Otherwise it opens a new pull request into the scanned
  branch.
- If the model judges the finding a false positive, it changes nothing.
- 3 credits are charged. They are refunded if it fails or the model finds
  nothing to change.

**Turning it on or off:** there is no switch in the workspace. A fix pull
request is only created when someone selects the button. To prevent it,
keep people who should not start one as members or viewers.

**Common problems**

- **"Connect this project's GitHub App so AI can open pull requests."**
  Finish **Connect GitHub** in the project's **Settings**. The button stays
  grey until then, as in the screenshot above.
- **Not enough credits.** The dialog shows the balance. An owner buys
  credits in **Billing**.
- **The button is missing for a file.** The language is not one of the
  three above.

## Weekly cleanup pull requests

**For:** removing unused code a little at a time, without anyone having to
remember.

**Who:** an owner or admin turns it on. The project must be connected
through the Skylos GitHub App and have a trusted CI scan of its default
branch.

1. Open the project's **Overview** and scroll to **Weekly cleanup PRs**.
2. Select **Turn on weekly cleanup PRs**.

![Weekly cleanup PRs on the project Overview. Off, because this project is not connected to GitHub yet.](img/cloud/fixes-weekly-cleanup.png)

**What it does**

- Every Monday at 14:00 UTC Skylos opens one pull request that deletes
  unused Python functions: up to 10 functions in up to 5 files, taken from
  the latest trusted scan of the default branch.
- In a published library it only removes functions whose names start with
  an underscore.
- It opens at most one pull request every 6 days, and none while an earlier
  one is still open.
- Each pull request costs 3 credits. When credits run out, that week is
  skipped.
- After two cleanup pull requests are closed without merging, it pauses.
  The badge shows **Paused**; **Resume weekly cleanup PRs** starts it
  again.

**Turning it off:** select **Turn off weekly cleanup PRs** in the same
place. The badge shows **Off**, **On** or **Paused**, and "Next run" shows
the next date.

Today the weekly pull request covers Python functions only. The manual
cleanup below works from every unused-code finding.

## Clean up by hand

**For:** working through quality, AI-code and unused-code findings one
focused change at a time.

Open the project, then **Overview**, **More actions**, **Clean up dead
code** (or the **Issues** tab's cleanup link). The **Dead-code cleanup**
page builds a task queue from a scan you choose.

1. Pick the **Branch** and the **Source scan**.
2. Work through the tasks. Each has its location, the evidence and the
   source revision. **Copy task** gives all of that to an agent.
3. Make the change, push, and scan again. **Compare against** shows what
   the new scan no longer finds.

Where the GitHub App is connected, **Create cleanup PR** opens a pull
request for a proposed removal. It costs 3 credits, like a fix pull
request.

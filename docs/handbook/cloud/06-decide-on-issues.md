# Decide on issues

Not every issue gets fixed. Cloud records the decision, who made it, why,
and until when, so the issue stops blocking and an auditor can see the
reasoning later.

There are three decisions, all behind one button, **Not fixing this**:

| Choice | Use it when | What it does |
|:--|:--|:--|
| False positive | The scanner is wrong about this code. | Hides the issue in future scans. |
| Accepted risk | The issue is real, and you will live with it for now. | Hides the issue until a date. On that date it comes back and counts again. |
| Let this merge anyway | One failed scan must merge now. | Marks that scan's gate as passed. The issues stay open. See "Merge anyway" in the gate chapter. |

A separate button, **This looks wrong**, sends feedback to Skylos. It
changes nothing in your workspace.

## Mark an issue "Not fixing this"

**For:** an issue you will not fix, or not yet.

**Who:** a member, admin or owner. Viewers cannot.

1. Open the issue, from a scan or from **Issues**.
2. Select **Not fixing this**.
3. Choose **False positive** or **Accepted risk**.
4. Type the reason. On the Workspace plan it needs at least 8 characters,
   so the approver knows why.
5. Under **Until when?** choose 7, 30 or 90 days.
6. Select **Send to an admin for approval**.

![Not fixing this. (1) The choice. (2) The reason. (3) The end date. (4) Send.](img/cloud/decide-not-fixing.png)

**What happens next** depends on the plan:

- **Workspace plan:** the decision becomes a request. The issue stays open
  until an admin or owner approves. You see "Approval request sent to an
  admin." If you are the only person who could approve, the issue is hidden
  at once and the buttons read **Hide as a false positive** or **Accept the
  risk**.
- **Free plan:** there is no approval step. The issue is hidden at once.
  An end date is required, and a project can hold 25 hidden issues.

For a false positive, the box **Also tell Skylos this finding is wrong**
sends the rule, file, line and your reason to Skylos so the scanner can be
fixed. It never sends code.

## Approve or reject a request

**For:** the second pair of eyes on a decision.

**Who:** an admin or owner, on the Workspace plan. You cannot approve your
own request.

1. Open **Not fixing**. The **Waiting for approval** tab lists the requests,
   newest first, with the reason and who asked.
2. Select **Review and decide** on a request.
3. Read **The risk**, **What approving covers** and **Why the requester
   wants to accept it**.
4. Select **Approve** (it shows the end date) or **Reject** (keep the issue
   open). You can add a note for the record.
5. Confirm with **Approve until** and the date.

![Waiting for approval. (1) The tab. (2) Review and decide.](img/cloud/decide-waiting.png)

![One request. (1) Approve until the end date. (2) Reject and keep the issue open.](img/cloud/decide-approve.png)

**What happens next:** an approved issue is hidden until its end date and
stops counting against the gate. After that date the decision ends on its
own and the issue counts again. The requester and the approver get an email
14 days, 7 days and on the day before it ends, where email is set up.
The decision, your name and your note go into the decision history and the
audit log.

## The "Not fixing" list

**Not fixing** in the sidebar is the record of every decision.

| Tab | What it lists |
|:--|:--|
| Waiting for approval | Requests nobody has decided yet. |
| False positives | Issues hidden as false positives without an approval step. |
| Recorded | Approved requests and accepted risks, soonest end date first. "Ending soon" marks those within 30 days. |
| Merged anyway | Failed scans that were merged anyway, with the reason and who did it. |
| Rules for every repo | Rules that hide one kind of issue in every repository. |

![The Recorded tab: each decision with who decided, when, and until when.](img/cloud/decide-list.png)

To end a decision early, open it from **Recorded** with **Open the request
to revoke it**. **Download all decisions (CSV)** exports the list (Workspace
plan).

**Rules for every repo:** an owner or admin can open an issue and choose
"Not a problem in any repo". Secrets and high or critical security issues
cannot be hidden this way. They need a decision per repository.

## How decisions appear later

- **In scans:** the issue stays in the list with a NOT FIXING tag. It no
  longer blocks.
- **On Issues:** filter **Status** by "Not fixing".
- **In Audit evidence:** "Decisions & policy history" lists what the team
  chose not to fix and who approved each.
- **In compliance reports:** hidden critical and high findings are listed
  with their reason, approver and end date. A critical or high finding that
  was hidden without a second person's approval is reported as a deviation.
  Get the approval before you generate a report. When you are the only
  possible approver, the form warns: "Compliance reports will list this as
  hidden without an approval record", with a link to add a second admin.

## This looks wrong

**For:** telling Skylos the scanner got something wrong: not a real
problem, a wrong explanation, or the wrong code shown.

**Who:** any member.

1. Open the issue and select **This looks wrong**.
2. Pick what is wrong and, if you like, add one sentence.
3. Select **Send to the founder**.

![Tell Skylos this looks wrong.](img/cloud/decide-looks-wrong.png)

**What it does:** the rule, file and line, the scan, your account and your
workspace go privately to the Skylos founder. Code and file contents are
never sent. You get a reference number, and the report and any reply are
listed under **Settings**, **General**, **Your reports**.

**What it does not do:** it does not change this scan, the gate or the
issue. To stop the issue from blocking, use **Not fixing this**.

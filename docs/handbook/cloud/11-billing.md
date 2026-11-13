# Billing and credits

Skylos sells two things: a yearly plan, and credits. They are separate. A
plan decides what the workspace can do. Credits pay for a few specific
actions and work on every plan, Free included.

**Who:** only an owner can buy, manage renewal and see the credit history.
Members and admins can spend credits. Everyone sees the balance under
their name at the bottom of the sidebar.

## Plans

| | Free | Workspace | Growth | Enterprise |
|:--|:--|:--|:--|:--|
| Price | $0 | $3,000 a year | $12,000 a year | From $30,000 a year, sold by hand |
| Projects | 1 | Up to 10 | Up to 50 | Up to 9,999 |
| Members | You, and people already in | Unlimited | Unlimited | Unlimited |
| Credits included each year | None | 1,000 | 3,000 | 5,000 |
| Scans kept per project | 10 | 500 | 500 | 10,000 |
| Single sign-on | No | No | Yes | Yes |

The Workspace plan adds, over Free: changing Policy, the approval step for
"Not fixing", Merge anyway, pull request comments, teams, Slack, Discord,
Jira and webhooks, downloads (CSV, JSON), and more projects and history.
Enterprise adds an audit export of who wrote each change, a person or an AI
agent.

Open **Billing** to see the plan you are on, the credit balance, the plans,
the credit packs, what each action costs, and recent credit activity.

![Billing: the plan, the balance, the two yearly plans and the credit packs.](img/cloud/billing-plans.png)

## Buy or keep a plan

1. Open **Billing**.
2. Under **Keep the Workspace plan**, pick **Workspace** or **Growth**.
3. Select the button on the plan and pay in the checkout that opens.

**What happens next:** you come back to Billing, which says "Purchase
verified" once the payment is confirmed. The plan starts and the year's
credits are added.

Two other states you can meet on this page:

- **"Email the founder to start."** Card checkout for that plan is not open
  yet. The button opens your email app; Skylos replies with a payment link.
- **"Buying is paused while we finish setting up payments."** No card is
  charged and nothing in your workspace changes. The banner links to where
  to ask.

## Renewal

A plan is paid by the year and renews each year until you turn renewal
off.

1. Open **Billing** and select **Manage renewal** (owners only). It opens
   the payment provider's page for your subscription.
2. Turn renewal off there.

With renewal off, Billing shows "Renewal is off. The plan runs until" the
end date "and nothing more is charged". The plan runs to the end of the
year already paid for. Each payment covers 12 months plus 7 days of grace.
Owners get an email before each renewal.

When a plan or the trial ends, the workspace moves to Free. Data and
credits are kept. See "The trial and the Free plan" in the first chapter
for what pauses.

## Credit packs

A pack adds credits and nothing else. It does not turn on the Workspace
plan. Credits never expire.

| Pack | Credits | Price |
|:--|:--|:--|
| Starter | 50 | $9 |
| Builder | 250 | $39 |
| Team | 1,000 | $129 |
| Scale | 5,000 | $499 |

To buy: **Billing**, **Credit packs**, select the pack's button, pay.

## What each action costs

Uploading scans, pull request checks and the merge gate are free. So are
scans on your own machine.

| Action | Credits | Notes |
|:--|:--|:--|
| Compliance report | 500 | One report for one framework. Charged once; downloading it again is free. |
| Automatic fix pull request | 3 | Refunded if it fails or the model changes nothing. |
| Weekly cleanup pull request | 3 | Per pull request opened. Skipped when credits run out. |
| Deep scan | 10 | Where Deep scans is available. Refunded when no report is produced. |
| Logic-change report | 1 | Per pull request, once turned on for a project. |

![What each action costs, as Billing shows it.](img/cloud/billing-costs.png)

When the balance is too low, the action stops before anything is charged
and says how many credits it needs.

## Receipts and credit history

- **Receipts and invoices** come by email from the payment provider
  (Lemon Squeezy) after each payment. There is no invoice list inside
  Skylos.
- **Credit history:** **Billing**, **See credit history** (owners). Every
  change to the balance, newest first, with what it was spent on. Filter by
  Spend, Purchases, Refunds and Bonuses.

## Send feedback

**For:** telling Skylos about a bug, a wrong finding, an idea or a
question.

**Who:** anyone signed in.

1. Select **Send feedback** at the bottom of the sidebar.
2. Pick the type: Bug, Wrong finding, Idea or Question.
3. Say what happened.
4. Leave **Reply to me at** ticked if you want an answer by email.
5. Select **Send to the founder**.

![Send feedback.](img/cloud/billing-send-feedback.png)

It goes privately to the founder. **Attached automatically** shows what is
sent with it. Nothing is posted publicly. You get a reference number. Your reports and the replies are listed under
**Settings**, **General**, **Your reports**.

For a wrong finding, **This looks wrong** on the issue itself attaches the
rule, file and line for you.

# Screenshots for "Using Skylos Cloud"

The screenshots in `docs/handbook/img/cloud/` come from a local Skylos Cloud
with fictional data: the company is "Example Co", the people are at
`example.com`, the repositories are the small demo projects in
`demo-repos.yaml`. Never take them from production or a real account.

Retake them for each release, after checking the guide against the Cloud
commit you are documenting.

## What you need

- A checkout of the Skylos Cloud repository at the commit to document, with
  its `node_modules` installed.
- A local Skylos Cloud running from that checkout (`next dev --webpack`) on a
  throwaway PostgreSQL built from all its migrations, with stand-in sign-in.
  The maintainers' local harness does this; it is not part of this
  repository. The scripts here only need the app's address and a `psql`
  wrapper for its database.
- Google Chrome, and a released `skylos` command to scan the demo projects.
- Pillow in the Python environment that runs `optimize.py`.

## Settings

| Variable | Meaning |
|:--|:--|
| `HANDBOOK_CLOUD_REPO` | The Skylos Cloud checkout (Playwright and `yaml` are loaded from its `node_modules`). |
| `HANDBOOK_CLOUD_BASE` | Address of the local app. Default `http://localhost:3911`. |
| `HANDBOOK_CLOUD_PSQL` | A script that runs `psql` against the local database. |
| `HANDBOOK_CLOUD_WORK` | A scratch folder outside the repository: demo checkouts, raw screenshots, page text. |
| `HANDBOOK_CLOUD_SKYLOS` | The released `skylos` command used to scan and upload the demo projects. |
| `SKYLOS_BROWSER_CHANNEL` | `chrome` (default). |

## Steps

```bash
node seed-base.mjs       # workspace, people, projects, CI tokens, real CLI scans,
                         # a laptop upload and an AI app safety upload
node seed-history.mjs    # earlier scans, pull requests and a credit purchase
node capture.mjs         # every screenshot; or name groups: node capture.mjs gate policy
python optimize.py       # trim and shrink the referenced images into docs/handbook/img/cloud/
node render-pages.mjs <pdf> <first> <last> <out dir> <Cloud checkout>
                         # render PDF pages through Chrome to read the built chapter
```

`capture.mjs` writes raw 2x images and the visible text of each page to
`$HANDBOOK_CLOUD_WORK`. Decisions, approvals, merge anyway and a compliance
report are made through the real UI during the capture, so run the groups
in order on a fresh database. Read the text files next to the guide: a label that
changed in Cloud shows up there first.

Capture the compliance group last, on the newest Cloud commit: those pages
change most often.

## After retaking

1. Update `verified_against` in `../manifest.yaml` (commit and date).
2. Run `python scripts/build_handbook.py --check` and
   `SKYLOS_CLOUD_REPO=<checkout> python -m pytest -q test/test_handbook_coverage.py`.
   The second fails when Cloud has a sidebar or settings destination the
   manifest does not list, or when the checkout is not the verified commit.
3. Build the PDF and read the Cloud chapters page by page.

## Style

- 1440 px wide window, cropped to the panel the step is about.
- One pink box per control the text refers to, with a number when the steps
  are numbered. The marks are drawn in the page before the capture
  (`mark()` in `lib.mjs`).
- No real names, repositories, emails or tokens. Token values never appear
  in a capture: the token list shows ids, and a new token is not opened.

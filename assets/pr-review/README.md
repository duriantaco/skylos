# PR report button

`view-report-v1.svg` is the 192 × 40 pixel-art button used by
`skylos cicd review`. Its lettering and watchdog are self-contained SVG
geometry, with no fonts, scripts, or external images. The surrounding link
has accessible text through the image's `alt` attribute.

The renderer links to the current GitHub Actions run, including GitHub
Enterprise Server runs. It omits the button when no valid run URL is
available. Finding counts, gate verdicts, and sticky comment updates are
independent of the artwork.

## Delivery

The image is served from this repository's public `main` branch. Keep this
versioned filename stable; use a new filename when changing the artwork so
GitHub's image proxy can cache each version. Publish the image before users
adopt a renderer that references it.

Merge the change through normal CI and release the package through Release
Please. Workflows pinning the package must upgrade after that release.
Composite Action users must select the new commit or tag and use
`mode: review`. This change does not update the separately deployed Skylos
Cloud GitHub App comment renderer.

## Verification

Run the focused tests from the repository root:

```bash
pytest -q test/test_cicd_review_button.py test/test_cicd_pr_summary.py \
  test/test_cicd_review.py test/test_cicd_review_sticky.py \
  test/test_cicd_review_left_unused.py
```

After the image is publicly available, use a repository whose PR workflow
runs `skylos cicd review` with the updated package or Action:

1. Run the workflow on a test pull request. Check that the summary has one
   192 × 40 button, above **Details**, in light and dark themes and at mobile
   width. GitHub's image proxy must load the image.
2. Click it and confirm it opens that workflow run, with the expected summary
   and artifacts.
3. Push an update and check that the same summary comment is edited, with a
   link to the new run. If the update fixes previously reported findings,
   check that the comment also shows the existing resolved message.

GitHub's Markdown rendering API can verify the link and image markup without
posting a comment. A live PR check is still needed to verify image delivery.

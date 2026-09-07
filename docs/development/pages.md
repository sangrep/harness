# GitHub Pages delivery

The intended live developer documentation URL is
<https://sangrep.github.io/harness/>. A successful local build or CI preview artifact
is not proof that this URL is live. Availability remains unverified until a
maintainer activates the approved deployment and completes the HTTP/browser checks
below. No custom domain or product route is part of this component's deployment.

## Preview and publication are separate

The normal `Repository check` builds and scans `work/docs-site`, then uploads a
short-lived `harness-docs-preview` artifact. Pull requests and ordinary pushes do
not publish documentation. The separate `Publish developer documentation` workflow
only accepts a manual dispatch from this repository's `master` branch.

The workflow requires the exact accepted current master SHA. Both build and deploy
verify the dispatch SHA, checked-out bytes, current remote master and preconfigured
Pages destination. A changed master, disabled Pages, custom domain, non-workflow
publishing source or unexpected URL blocks publication. The workflow never enables
Pages, creates a custom domain or changes repository visibility/settings.
These are point-in-time checks; they do not lock master or Pages settings while
GitHub processes the deployment. Maintainer environment restrictions and final
verification remain part of acceptance.

Build uses read-only contents/Pages permissions, the existing immutable bootstrap,
strict docs/public-boundary checks and the digest-verified Gitleaks scanner over the
exact docs artifact. It uploads only `work/docs-site`, rejects a `CNAME` file and
keeps the Pages artifact for one day. Deploy depends on that build and uses only
contents-read, Pages-write and OIDC-write permissions in the `github-pages`
environment. It does not execute the bootstrap or build with deployment rights.

## Maintainer acceptance and activation

1. Accept component review/integration and resulting-master CI. Integrate this
   workflow only after the component implementation is accepted. A local successor
   prepared from an earlier candidate must be reapplied as only its Pages delta on
   the accepted resulting master before it is proposed or pushed.
2. Complete the current hosted-content audit and review/CI/branch-policy snapshot.
   Record the accepted source SHA and preserve the checked artifact evidence.
3. Under separate activation authority, configure GitHub Pages to use GitHub Actions
   and the default project URL with HTTPS. Configure the `github-pages` environment
   to allow only `master` and require the intended maintainer approval. These setup
   and visibility decisions are not performed by the workflow.
4. Manually dispatch `pages.yml` on `master`, supplying that exact commit as
   `source_sha`. If master moves before deployment, obtain a new accepted snapshot
   and dispatch for the newly accepted current master; do not override the guard.
5. Record the successful build/deploy run, exact source/artifact identities and
   reported default URL. Then verify the root, quickstart and API-reference pages,
   navigation, CSS/JS and search assets over credential-free HTTPS and in a browser.
   Check project-path links under `/harness/`, HTTPS and absence of custom-domain
   redirects. Only after those observations may the docs be called live.
6. Reconcile the measured Pages delivery on [Issue #1](https://github.com/sangrep/harness/issues/1).
   Preview-only evidence does not close the live-documentation acceptance.

The workflow does not rerun component tests: it consumes the maintainer's accepted
master/CI decision and rebuilds/scans the documentation from those exact bytes.
Normal required CI remains unchanged. A deployment workflow result alone does not
qualify product behavior, live providers, package release or support commitments.

## Platform references

The job split, Pages artifact format, environment and permissions follow
[GitHub's custom Pages workflow guidance](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages),
[upload-pages-artifact](https://github.com/actions/upload-pages-artifact) and
[deploy-pages](https://github.com/actions/deploy-pages). Action revisions are pinned
in the workflow; updating them requires review of that separate supply-chain input.

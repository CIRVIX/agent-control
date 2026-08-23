# CIRVIX — Human Unblock Instructions

Three external credentials block the launch path. Each unblock below is written
so a human with browser access to the relevant account can complete it in
minutes. Nothing else is blocked on people.

---

## 1. npm trusted publishing → `@cirvix/agent-control`

**Where you must be logged in:** npm as a member of the `cirvix` npm
organization (or its owner).

1. Go to <https://www.npmjs.com/settings/cirvix/packages> and confirm an org
   named **`cirvix`** exists. If not: create it (free "unlimited public
   packages" plan suffices) at <https://www.npmjs.com/org/signup>.
2. Create a **granular access token**: <https://www.npmjs.com/settings/~/tokens/granular-access-tokens/new>
   - Token name: `github-agent-control-publish`
   - Expiration: 12 months (calendar)
   - Packages and scopes: **Read and write** on scope `@cirvix`
   - Permissions: no org/team admin needed
3. Copy the token (`npm_…`).
4. Go to <https://github.com/CIRVIX/agent-control/settings/secrets/actions> →
   **New repository secret**:
   - Name: `NPM_TOKEN`
   - Secret: paste the token
5. Done. The release workflow's `publish-npm` job gates on exactly this secret;
   it runs automatically when a `v*` tag is pushed.

**Verify afterwards:** push a tag (`git tag v0.1.0 && git push origin v0.1.0`),
watch <https://github.com/CIRVIX/agent-control/actions>, then run:

```
npm view @cirvix/agent-control version   # should print 0.1.0, not 404
```

## 2. PyPI trusted publishing → `cirvix`

**Where you must be logged in:** PyPI as an owner of the `cirvix` project (or
create it first — one-time "pending publisher" registration below covers both).

1. Go to <https://pypi.org/manage/account/publishing/>
2. Under **"Add a new pending publisher"** (or **"Add a trusted publisher"**
   inside the existing `cirvix` project at <https://pypi.org/manage/project/cirvix/settings/publishing/>):
   - PyPI project name: **`cirvix`**
   - Owner: **`CIRVIX`**
   - Repository: **`agent-control`**
   - Workflow name: **`release.yml`**
   - Environment name: **`pypi`**
3. Save. No token exists to copy — GitHub's OIDC identity is the credential.
4. The GitHub side already declares `environment: pypi` and `id-token: write`;
   the environment itself was created during this session.

**Verify afterwards:** same tag push; then:

```
pip index versions cirvix    # or: curl -s https://pypi.org/pypi/cirvix/json | head
```

## 3. Paddle billing → live checkout

**Where you must be logged in:** <https://vendors.paddle.com> (Paddle Billing,
not Classic), account for Cirvix.

1. **Create products/prices** (Catalog → Products) — four, matching
   `assets/pricing.js` exactly:
   | Product | Price (monthly) | Annual |
   |---|---|---|
   | Cirvix Starter | $29 / month | $290 / year |
   | Cirvix Pro | $79 / month | $790 / year |
   | Cirvix Team | $149 / seat / month (min 3 seats) | $1,490 / seat / year |
   Free needs no product.
2. Copy each **price id** (`pri_…`) for all six prices.
3. **Client-side token** (Developer tools → Authentication): copy the token
   beginning `live_`. It is safe to publish — it can only open a checkout, not
   create one. Never put the API key (`pdl_…`) in the site.
4. Open `final/assets/pricing.js`, find the `CHECKOUT` constant (~line 30) and
   fill in:
   ```js
   const CHECKOUT = {
     token: 'live_…',
     env: 'production',
     prices: {
       starter: { monthly: 'pri_…', annual: 'pri_…' },
       pro:     { monthly: 'pri_…', annual: 'pri_…' },
       team:    { monthly: 'pri_…', annual: 'pri_…' },
     },
   };
   ```
5. Commit + push `final/` — deploys automatically.
6. **Webhook**: Developers → Notifications → add destination
   `https://<control-plane-host>/webhooks/paddle` subscribed to
   `transaction.completed`, `subscription.canceled`,
   `subscription.payment_failed`, `subscription.updated`.
7. **Test before launch day** with `env: 'sandbox'` + sandbox token first:
   buy Starter monthly with test card `4242 4242 4242 4242`, confirm webhook
   grants entitlement, cancel, confirm revoke, force a failed payment.

**Verify afterwards:** paid-tier buttons on `/pricing.html` open Paddle
checkout instead of the contact modal.

---

*Prepared 2026-08-23 by the launch operator session. Everything machine-side
(workflows, environments, gating, verification commands) is already in place.*

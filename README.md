# ea-plugin-outlook-web-auth

Graph tokens from Outlook on the web, for a Microsoft 365 tenant that
gives the EA no app registration. An owner-zone plugin for EA core
(`docs/plugins.md` in ea-system): its code runs as the owner, with the
owner's tokens, from the owner-private plugins directory.

It declares two owner hooks:

| Hook | What it does |
|---|---|
| auth source `manual-token` (`auth_sources.py:manual_token`, kind `graph`) | Returns the token in `~/.ea/auth/manual_token.txt` when it is for Microsoft Graph or the Outlook REST API and has more than a minute left. `graph_client.authenticate` asks it after the MSAL cache and before any interactive sign-in. |
| cron `harvest` (`*/30 * * * *`) | A headless browser harvest that rewrites that file with a fresh token (`outlook_web.py refresh`), through `ea-plugin.py run-owner outlook-web-auth harvest`. Add it only on an install that uses the harvest. |

EA core keeps MSAL silent refresh, the confidential client and the
public-client device-code and interactive flows. With an app
registration, use those (SETUP.md Step 5); this plugin is the path when IT
will not grant one, and a bootstrap for a short outage.

## Two ways to fill the token file

### A pasted token (bootstrap or a short outage only)

You copy a token from the browser's developer tools and paste it into the
file. Both forms work:

*Browser localStorage:*
1. Open outlook.office.com
2. DevTools (F12) > Application > Local Storage > outlook.office.com
3. Find an `msal.*` key whose `target` contains
   `https://graph.microsoft.com`
4. Copy its `secret` value

*Network tab:*
1. DevTools (F12) > Network > filter `graph.microsoft.com`
2. Click any request > Headers > copy the value after
   `Authorization: Bearer `

Then save it:

```bash
echo "YOUR_TOKEN_HERE" > ~/.ea/auth/manual_token.txt
chmod 600 ~/.ea/auth/manual_token.txt
```

**Validation done for you.** `manual_token()` decodes the JWT and refuses
a token whose `aud` is not one of Microsoft Graph
(`00000003-0000-0000-c000-000000000000` or `https://graph.microsoft.com`)
or the Outlook REST API (`https://outlook.office.com`), and refuses one
with under 60 seconds left, printing the expiry and the account it
belonged to. A token it cannot decode at all is used anyway, with a
warning.

A browser-issued Graph token lasts about an hour and nothing rewrites the
file for you unless the harvest runs, so this is a bootstrap step, not a
daily workflow.

### The browser harvest (no app registration)

The path when the tenant blocks app registrations entirely. A Playwright
script opens Outlook in a headless browser, reads the access token that
Outlook keeps in localStorage, and saves it. The browser reuses the SSO
cookies, so no sign-in is needed after the first time. It piggybacks on
Outlook on the web's own MSAL.js token cache, which Microsoft's code
maintains; the token carries Mail and Calendar scopes because it is the
same token Outlook uses itself.

Requires Playwright and its Chromium in the owner's Python (the
interpreter `ea-plugin.py` runs under):
`pip install playwright && playwright install chromium`.

```bash
# First time: a visible browser; sign in to your SSO
EA_CORE_DIR=/opt/ea-system python3 ~/.ea-private/plugins/outlook-web-auth/outlook_web.py login

# Verify it worked
EA_CORE_DIR=/opt/ea-system python3 ~/.ea-private/plugins/outlook-web-auth/outlook_web.py check
```

Then add the cron line `ea-plugin.py cron-lines` prints for
`outlook-web-auth`: a headless harvest every 30 minutes, skipped while the
token has more than 15 minutes left (`refresh --force` harvests anyway).

| Component | Lifetime | What happens | Recovery |
|---|---|---|---|
| Access token | ~24 hours | API calls return 401 | The next cron run gets a new one |
| SSO cookies | ~90 days | The headless harvest lands on the sign-in page | Run `login` again |

Alerts (to the EA channel, with the bot's credentials): when a headless
harvest fails (SSO expired, or no token in storage), and when the SSO
cookies are within 7 days of expiry.

`GRAPH_AUTH_METHOD=playwright` in `~/.ea/.env` is no longer read by the
core; the auth source applies whatever the method. Leave it, or remove it.

## Graph or Outlook REST

Many institutions block third-party Graph app registrations
(AADSTS1001010), but the Outlook REST API needs none. If a colleague can
sign in to outlook.office.com in a browser, the harvest gets a working
token. `manual_token()` accepts the Outlook REST audience on purpose, and
`graph_client` routes such a token to `https://outlook.office.com/api/v2.0`
and normalizes the response keys.

1. Run `outlook_web.py login` and sign in to your organization's SSO.
2. The harvest prefers a Graph token with mail scopes, then an Outlook
   REST one.
3. With `aud: https://outlook.office.com` you are on the REST path:
   everything works except flagged-message detection.
4. With `aud: https://graph.microsoft.com` you have full Graph access.

## Install

As the owner, on the EA host:

```bash
python3 /opt/ea-system/scripts/ea-plugin.py install git:git@github.com:<owner>/ea-plugin-outlook-web-auth.git
```

It prints the capabilities and stops: an owner-zone plugin always needs
consent. Read them, then run it again with `--accept-capabilities`. On a
harvest install, add the cron line (above). The auth source needs no
restart: each owner process reads the lock when it authenticates.

Updates: push, then `ea-plugin.py update outlook-web-auth`.

## Files

| Path | What |
|---|---|
| `~/.ea/auth/manual_token.txt` | the Graph or Outlook REST token: 0600 under mail mediation, 0640 group ea without (`owner_trust.token_file_mode`) |
| `~/.ea-private/playwright-outlook/` | the browser profile with the Outlook SSO cookies (owner only) |
| `~/.ea-private/logs/outlook-web-auth.log` | the harvest's own log |
| `~/.ea-private/logs/plugin-outlook-web-auth-harvest.log` | the cron job's output |

A profile still under `~/.ea/auth/` (an older install) is used while it
passes the owner checks, with a warning; move it with
`outlook_web.py migrate-profile`. The SSO cookie check reads the store
only through owner_trust's checked descriptors, from a private copy.

## Token flow

```
                    ┌────────────────────┐
                    │  Cron (*/30 min)   │
                    └─────────┬──────────┘
                              │
              ┌───────────────▼────────────────┐
              │ ea-plugin.py run-owner          │
              │ outlook-web-auth harvest        │
              └───────────────┬────────────────┘
                              │
              ┌───────────────▼──────────────┐
              │ Playwright (headless Chrome) │
              │  persistent browser context  │
              │  reuses SSO cookies (~90d)   │
              └───────────────┬──────────────┘
                              │
                    ┌─────────▼────────┐
                    │ Navigate to       │
                    │ outlook.office365 │
                    │ .com/mail/        │
                    └─────────┬────────┘
                              │
              ┌───────────────▼──────────────┐
              │ Read MSAL token cache from   │
              │ localStorage via JavaScript  │
              └───────────────┬──────────────┘
                              │
                   ┌──────────▼─────────┐
                   │ Validate JWT:      │
                   │ - correct audience │
                   │ - >5 min remaining │
                   └──────────┬─────────┘
                              │
                    ┌─────────▼────────┐
                    │ Save to          │
                    │ manual_token.txt │
                    └─────────┬────────┘
                              │
              ┌───────────────▼──────────────┐
              │ Check SSO cookie expiry      │
              │ from the Chromium cookie DB; │
              │ alert if < 7 days            │
              └──────────────────────────────┘
```

## Moving from the core's copy

Earlier EA core releases carried this code (`graph_client.get_manual_token`,
step 3 of `authenticate`, and `token_refresh.py` with `--login`, `--check`
and `--force`). The token file and the browser profile keep their paths,
so nothing moves. `token_refresh.py --login` is now `outlook_web.py login`,
`--check` is `check`, and the `*/30` crontab line that ran
`token_refresh.py` becomes the one `ea-plugin.py cron-lines` prints.

## Tests

```bash
EA_CORE_DIR=/path/to/ea-system python3 -m pytest -q -p no:cacheprovider tests
```

The tests use made-up tokens, a scratch EA tree and a scratch
owner-private directory; `test_install.py` installs this working tree
through EA core's `plugin_install` and has `graph_client.authenticate`
take the token from it.

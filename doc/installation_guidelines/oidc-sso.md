# Single Sign-On (OpenID Connect)

This page describes how to let users sign in to Hashtopolis with an external identity provider such as Microsoft Entra ID or Keycloak.

Hashtopolis acts as a confidential OpenID Connect client (authorization code flow with PKCE and a client secret). The provider's tokens never reach the browser, and all settings live in environment variables on the server.

Single sign-on only works for existing users: an account has to be **linked** to an identity at the provider before it can sign in with it. Hashtopolis never creates users from a login.

## Requirements

- The identity provider must be reachable from the Hashtopolis backend over HTTPS (outbound port 443 to the provider). The backend fetches the discovery document, the signing keys and the tokens itself.
- The callback address `https://<host>/api/v2/auth/oidc/callback` must be reachable from the browsers of your users.
- Discovery data and signing keys are cached on disk in the `oidc-cache` folder inside the Hashtopolis config directory. That folder must be writable by the web server user.
- The frontend origin users sign in from has to be trusted by the backend, see `HASHTOPOLIS_FRONTEND_URLS` in the [Basic installation](../installation_guidelines/basic_install.md) page.

## Configuration

Single sign-on is enabled as soon as `HASHTOPOLIS_OIDC_ISSUER` is set. Set the variables in the `.env` file next to your `docker-compose.yaml` (the `env.*.example` files list them commented out), then restart the server container.

| Variable | Default | Meaning |
|---|---|---|
| `HASHTOPOLIS_OIDC_ISSUER` | unset | Issuer URL. Setting it enables single sign-on. It has to match the issuer the provider publishes character for character, including a trailing `/` if the provider has one. |
| `HASHTOPOLIS_OIDC_CLIENT_ID` | unset | Client (application) ID. Required when single sign-on is enabled. |
| `HASHTOPOLIS_OIDC_CLIENT_SECRET` | unset | Client secret. Required when single sign-on is enabled. |
| `HASHTOPOLIS_OIDC_SCOPES` | `openid profile email` | Requested scopes. Must include `openid`. |
| `HASHTOPOLIS_OIDC_DISPLAY_NAME` | `SSO` | Label of the sign-in button. |
| `HASHTOPOLIS_LOCAL_LOGIN_ENABLED` | `true` | Set to `false` to turn off password login. Ignored, with a log message, if single sign-on is not fully configured. |

An empty value counts as unset. If the issuer is set but the client ID or secret is missing, the single sign-on endpoints answer as if it were disabled and an error is logged.

The redirect URI to register with the provider is the backend URL plus `/auth/oidc/callback`, for example `https://hashtopolis.example.com/api/v2/auth/oidc/callback`.

!!! warning
    `HASHTOPOLIS_OIDC_ALLOW_INSECURE_HTTP=true` allows `http://` provider URLs. It exists for development and automated tests only. Never set it on a production server.

## Microsoft Entra ID

1. In the Azure portal open **Microsoft Entra ID**, then **App registrations**, then **New registration**.
2. Choose the supported account type **Accounts in this organizational directory only** (single tenant).
3. Under **Redirect URI** choose the platform **Web** and enter `https://<host>/api/v2/auth/oidc/callback`.
4. After registering, copy the **Application (client) ID** and the **Directory (tenant) ID** from the overview page.
5. Under **Certificates & secrets** create a **New client secret** and copy its **Value** right away. It is only shown once.
6. Configure Hashtopolis:

```bash
HASHTOPOLIS_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
HASHTOPOLIS_OIDC_CLIENT_ID=<application-client-id>
HASHTOPOLIS_OIDC_CLIENT_SECRET=<client-secret-value>
HASHTOPOLIS_OIDC_DISPLAY_NAME=Microsoft
```

Use the exact tenant ID in the issuer, without a trailing slash. Do not use `/common` or `/organizations`: tokens from those endpoints carry the real tenant in their issuer, so they never match.

## Keycloak

1. In the admin console create or choose a realm.
2. Under **Clients** create a client with client type **OpenID Connect**, enable **Client authentication** and the **Standard flow**.
3. Set **Valid redirect URIs** to `https://<host>/api/v2/auth/oidc/callback`.
4. Under **Credentials** copy the client secret.
5. Configure Hashtopolis:

```bash
HASHTOPOLIS_OIDC_ISSUER=https://keycloak.example.com/realms/<realm>
HASHTOPOLIS_OIDC_CLIENT_ID=<client-id>
HASHTOPOLIS_OIDC_CLIENT_SECRET=<client-secret>
HASHTOPOLIS_OIDC_DISPLAY_NAME=Keycloak
```

The issuer is the address that the realm's `/.well-known/openid-configuration` document lists as `issuer`.

## Linking users

Hashtopolis recognises a user by the pair of the provider's issuer and the token's `sub` claim. It never matches on email address or username. Those can change or be handed to someone else (for example a reassigned email address or user principal name), and trusting them would let a different person take over an account. Note that Entra ID issues a `sub` that is unique per application: registering Hashtopolis a second time creates a new identity for the same person, which has to be linked again.

There are two ways to link an account:

- **From the account settings.** A signed-in user opens their account settings, chooses to link a single sign-on identity and enters their current Hashtopolis password. They are sent to the provider and, on return, the identity is linked. The same page lists the linked identities and lets the user unlink them.
- **At the first single sign-on login.** If the identity is not linked yet, the login page asks for the Hashtopolis username and password once. When they are correct, the identity is linked and the user is signed in.

Linking always needs the current Hashtopolis password, so a stolen session cannot add a permanent way into an account. An identity can only be linked to one user at a time.

## Turning off password login

Set `HASHTOPOLIS_LOCAL_LOGIN_ENABLED=false` once single sign-on works. Password login (`/auth/token`) and the password reset routes then answer 403. API keys, agent authentication and `/auth/oauth-token` are not affected.

Linking at the first login still accepts a Hashtopolis password while local login is off. That only works for someone who has just signed in at the provider. To onboard a user with local login off:

1. An administrator creates the user, or resets their password, and sets a temporary password.
2. The user signs in with single sign-on and enters their username and the temporary password when asked.
3. From then on the user signs in with single sign-on only.

## The existing `/auth/oauth-token` endpoint

`/api/v2/auth/oauth-token` is separate from this feature and has not changed. It has known gaps that single sign-on does not share:

- it does not check `iss` or `aud`, so any token signed by a key listed in `jwks.json` is accepted, whichever client it was issued to;
- it maps users by `preferred_username`;
- the provider's keys have to be pasted into `jwks.json` by hand.

Use the single sign-on described on this page for new setups.

## Troubleshooting

When single sign-on fails, the browser is sent back to Hashtopolis with a short reason code in the address. Failed logins land on the login page; failed or finished link requests land on the account settings page. The details are in the Hashtopolis log, never in the address.

| Address contains | Meaning | What to do |
| --- | --- | --- |
| `sso=error&reason=expired` | The sign-in request is unknown, expired (requests last 10 minutes) or was already used, or the browser did not send its sign-in cookie back. | Start again from the login page. If it keeps happening, check that the browser accepts cookies. If the frontend runs on a different site than the backend, set `HASHTOPOLIS_REFRESH_COOKIE_SAMESITE=None` (see the advanced installation guide). |
| `sso=error&reason=provider_error` | The provider reported an error, or the token exchange or ID token check failed (wrong client secret, issuer mismatch, unreachable provider, clock skew). | Check the Hashtopolis log for the entry "Single sign-on failed", then the issuer, client ID, client secret and redirect URI. |
| `sso=error&reason=user_disabled` | The linked Hashtopolis user is disabled. | Ask an administrator to enable the user. |
| `sso=error&reason=already_linked` | A link request was made for an identity that belongs to a different Hashtopolis user. Shown on the account settings page. | Unlink the identity from the other user first, or sign in to the provider as a different person. |
| `sso=link-required` | The provider identity is valid but not linked to any Hashtopolis user yet. This is expected on the first login. | Enter the Hashtopolis username and password when the login page asks, as described under "Linking users". |

## Endpoints

All endpoints are listed in the API documentation under `/api/v2/auth/oidc/`: `config`, `login`, `callback`, `link`, `link-pending` and `identities`.

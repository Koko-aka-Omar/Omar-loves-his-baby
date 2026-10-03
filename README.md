# Our private little place

This local preview protects the entire website and separately protects the secret diary. Passwords and encryption keys live in private server settings outside this folder. Only encrypted page and diary payloads are included here.

The diary keeps its food hint and three-key hunt. Progress is saved in the browser, while password access is checked by the server. The diary text is fetched separately after its password is accepted; it is absent from the website HTML.

The three discovery hints are encrypted separately. The server releases them on 5, 8 and 7 October 2026, respectively, at 11:59 p.m. Dubai time. Before each release, the browser receives only a deadline and the server's time, which anchors its live countdown. Collecting keys and opening the diary remain possible before any hints arrive.

The entrance session lasts six hours. The diary session lasts up to two hours and belongs to that entrance session. “Lock our little place” revokes access, including the diary, and clears the displayed page. Sessions use opaque HttpOnly cookies, with Secure cookies on the deployed HTTPS site. Eight password attempts are allowed in fifteen minutes. The entrance limit is shared across the site; the diary limit is per entrance session.

## Local preview

The existing local preview reads its ignored private settings from the workspace’s `work/private` folder. The server only binds to the local computer. To restart it from the workspace, run `node work/private-preview.cjs`.

## Hosting and recovery

This is a Node server application, replacing the old static HTML deployment. The Vercel configuration uses its Node framework preset and `server.cjs` entrypoint. Deployment routing and private settings must be verified on an authorized preview before production.

Configure these private server environment variables; do not put their values in GitHub or browser-visible variables:

- `KARMEL_CONTENT_KEY`: the existing random content key used to seal this build.
- `KARMEL_SITE_PASSWORD_HASH`: the existing salted scrypt entrance verifier.
- `KARMEL_DIARY_PASSWORD_HASH`: the existing salted scrypt diary verifier.
- `KARMEL_ORIGIN`: the exact HTTPS origin of the deployment.
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`: a private Redis store for shared session revocation and attempt limits. The Vercel Upstash integration's `KV_REST_API_URL` and `KV_REST_API_TOKEN` names are also accepted.

The deployed application refuses to serve private pages if required settings or the private session store are missing. Do not set the local file store on Vercel. Upload only this folder, never the workspace’s plaintext `work` sources or private settings. Keep a secure backup of the content key; the encrypted pages cannot be recovered without it.

Previously published passwords and letters remain in the public repository’s history and any existing copies. This build cannot retract those copies. Protecting or removing historical material is a separate action, requiring review before changing the public repository or live deployment.

Platform reference: [Vercel Node server entrypoints](https://vercel.com/docs/functions/runtimes/node-js). Security references: [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), and [GitHub sensitive-data removal](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

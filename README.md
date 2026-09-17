# @stefanobalocco/honosessionsmanager

Server-side sessions for [Hono](https://hono.dev). Session data lives in your storage behind a small pluggable interface. The browser holds only one cookie: a compact encrypted credential. There is no JWT and no signed payload to inspect. Session data remains server-side; the browser receives only this encrypted credential, which contains the session ID and the 256-bit secret that authenticates it.

## Installation

```sh
npm install @stefanobalocco/honosessionsmanager
```

Peer dependency: `hono` ^4. Requires Node.js 22.20+, 24.12+, or 26+.

## Quick start

The factory is asynchronous because it generates or imports a Web Crypto key before the manager exists.

```typescript
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { SessionsManager } from '@stefanobalocco/honosessionsmanager';
import type { Session, SessionsEnv, Undefinedable } from '@stefanobalocco/honosessionsmanager';

const manager: SessionsManager = await SessionsManager.create();

const app: Hono<SessionsEnv> = new Hono<SessionsEnv>();

app.use( '*', manager.middleware );

app.post( '/login', async( context ) => {
  const session: Session = await manager.create( context );
  await session.data.set( 'userId', 42 );
  return context.text( 'Logged in' );
} );

app.get( '/me', ( context ) => {
  const session: Undefinedable<Session> = context.get( 'session' );
  if( session ) {
    return context.json( { authenticated: true } );
  }
  return context.json( { authenticated: false }, 401 );
} );

app.post( '/logout', async( context ) => {
  const token: Undefinedable<string> = getCookie( context, 'session' );
  await manager.delete( context, token ?? '' );
  return context.text( 'Logged out' );
} );

serve( { fetch: app.fetch } );
```

The default cookie name is `session`. If you configure `cookie.name`, pass the same name to manual `getCookie` calls, such as the logout route above.

## How it works

`manager.middleware` reads the configured cookie (default `session`) and, when present, verifies it. After the middleware, `context.get( 'session' )` returns a `Session` with data methods, or `undefined` when the request is unauthenticated. The middleware never creates sessions on its own.

Call the manager explicitly where login, logout, or session teardown happen:

- `manager.create( context )` — allocates a storage record, sets the configured cookie, stores the session in the context, and returns it.
- `manager.verify( context, token )` — decrypts and authenticates the token, checks the storage record, and returns the session or `undefined`. On success it reissues the same token cookie under the configured name with a fresh `Max-Age`; any failure leaves cookies unchanged.
- `manager.delete( context, token )` — removes the storage record and clears the configured cookie. It returns whether the record was found and removed, and returns `false` (still clearing the cookie) for malformed or unknown tokens.

Typically you call `create` in your login route, `delete` in your logout route, and let the middleware handle verification for every request.

Because the middleware renews a valid cookie, a later `create` in the same request appends a second `Set-Cookie` header with the new token, and a later `delete` appends a deletion header after the renewal. Browsers apply these in order, so the last header wins.

## Storing session data

`session.data` is the only public session surface. It holds application data and nothing else:

```typescript
await session.data.set( 'cart', { items: [ 'book', 'pen' ] } );
const cart: Undefinedable<JSONValue> = await session.data.get( 'cart' );
await session.data.delete( 'cart' );
```

Values are JSON values: strings, numbers, booleans, null, arrays, and plain objects. `set` and `get` clone values, so later mutations of the object you passed in or received do not affect stored data.

Session IDs are not secret. They may be predictable and may be reused after deletion; authentication always requires both the ID and the secret inside the encrypted cookie.

## Storage

### Local storage

By default the manager uses `SessionsStorage.Local`, an in-memory store with a fixed capacity of 65,536 (`0x10000`) sessions:

```typescript
import { SessionsStorage } from '@stefanobalocco/honosessionsmanager';

const storage: SessionsStorage.Local = new SessionsStorage.Local();
```

Creation allocates the lowest free non-negative ID and slides expiry forward on every verified access. When occupancy reaches 75% of capacity, creation first sweeps out expired sessions. When no free ID remains, creation throws `Session array full`. Session data accepts only JSON values; the TypeScript contract is the validation boundary.

### Custom storage

Bring your own storage by declaring a class that implements the `SessionsStorage` interface the library exports, then instantiate it in the factory options:

```typescript
import { SessionsManager } from '@stefanobalocco/honosessionsmanager';
import type { SessionsStorage } from '@stefanobalocco/honosessionsmanager';
import { RedisSessionsStorage } from './storage/RedisSessionsStorage.js';

const storage: SessionsStorage = new RedisSessionsStorage();
const manager: SessionsManager = await SessionsManager.create( { storage } );
```

The compiler checks your class against exactly three method signatures, and each method may be synchronous or return a promise:

```typescript
create( secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<[ number, Session ]>;
verify( sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<Undefinedable<Session>>;
delete( sessionId: number, secret: Uint8Array<ArrayBuffer> ): Promisable<boolean>;
```

- `create` stores the secret in a fresh record and returns `[ sessionId, session ]`. The ID must be a non-negative safe integer in the inclusive range from `0` to `Number.MAX_SAFE_INTEGER`. `SessionsManager` treats this as part of the storage contract and does not revalidate or roll back an invalid ID returned by `create`. The returned session exposes only `data` methods backed by your record.
- `verify` compares the secret, applies your expiry rule, and returns the session or `undefined`. On success, update your stored last-use time; the sliding expiry window is yours to enforce.
- `delete` removes the record only when the secret matches, and returns whether it was removed.

Your storage owns the records, the IDs, and the expiry rules. Routes never see stored records, IDs, or secrets: a `Session` exposes only `data`.

## Configuration

```typescript
const manager: SessionsManager = await SessionsManager.create( {
  validityToken: 3_600_000,
  encryptionKey: keyBytes,
  storage: myStorage,
  cookie: { mode: 'strict', name: 'app.sid', path: '/', secure: true }
} );
```

| Option | Default | Meaning |
|--------|---------|---------|
| `validityToken` | `3_600_000` | Sliding validity window in milliseconds. Must be a positive safe integer no greater than `34_560_000_000` (400 days). |
| `encryptionKey` | Generated per manager | Optional raw AES key bytes as `Uint8Array<ArrayBuffer>`. 16, 24, and 32 bytes are accepted; the bytes are copied during manager creation. |
| `storage` | `SessionsStorage.Local` | Pluggable storage implementing `SessionsStorage`. |
| `cookie.domain` | Host-only | `Domain` attribute. When omitted the cookie is host-only. |
| `cookie.mode` | `'lax'` | `SameSite` policy and partitioning. See the mode table below. |
| `cookie.name` | `'session'` | Cookie name. Must be a valid cookie name: non-empty and matching `` `/^[\w!#$%&'*.^`|~+-]+$/` ``. The same configured name is used to read, issue, renew, and delete the cookie. |
| `cookie.path` | `'/'` | `Path` attribute. Must be a non-empty absolute path. |
| `cookie.secure` | `true` | `Secure` attribute. |

The cookie name defaults to `session` and is configurable through `cookie.name`. Hono enforces the `__Secure-` and `__Host-` prefix constraints when it serializes the cookie; the factory validates only the name syntax.

### Cookie modes

| Mode | SameSite | Partitioned | Secure required |
|------|----------|-------------|-----------------|
| `'strict'` | `Strict` | No | No |
| `'lax'` | `Lax` | No | No |
| `'cross-site'` | `None` | No | Yes |
| `'partitioned'` | `None` | Yes | Yes |

`'lax'` is the default. The factory rejects `'cross-site'` and `'partitioned'` when `secure` is `false`.

### Cookie lifetime

`SessionsManager` always enables `HttpOnly`. It derives `Max-Age` as `Math.ceil( validityToken / 1000 )` and never emits `Expires`. The default `validityToken` of `3_600_000` produces `Max-Age=3600`, so the default cookie is persistent for one hour rather than a browser-session cookie. Hono caps `Max-Age` at 400 days, which is why `validityToken` cannot exceed `34_560_000_000` milliseconds.

Set `secure: false` only for `'strict'` or `'lax'` over plain HTTP during development. Cross-site and partitioned cookies must be secure.

## Encryption

Sessions always use AES-GCM. There is no algorithm option to configure.

When you omit `encryptionKey`, `SessionsManager.create()` generates one non-extractable AES-128 key and the manager keeps that key for its lifetime. Every manager instance you create gets its own key, so tokens issued by one manager never verify against another.

When you supply `encryptionKey`, it must be the raw AES key bytes in a `Uint8Array<ArrayBuffer>`: 16 bytes for AES-128, 24 bytes for AES-192, or 32 bytes for AES-256. The manager copies the bytes during creation, so later mutations of your array do not affect it. To verify tokens across manager instances or processes — including after a restart — supply the same key bytes to each one.

Each token is a fresh random 12-byte IV followed by the ciphertext of the credential, authenticated with a 64-bit GCM tag.

Tokens created by earlier versions with the default AES-GCM configuration and a 64-bit tag stay compatible when you supply the same key bytes. Tokens created with a former custom algorithm or tag setting do not.

## Security and cookie behavior

- The cookie value is an encrypted blob: a fresh random 12-byte IV followed by the AES-GCM ciphertext of `[ sessionId, base64urlSecret ]`. The GCM authentication tag stays inside the ciphertext; the blob is canonical unpadded Base64URL.
- The 256-bit (32-byte) session secret never leaves the server except encrypted inside the cookie.
- Cookies are `HttpOnly`, `Secure`, and `SameSite=Lax` by default, and `cookie` selects the name, domain, mode, path, and secure flag.
- Invalid or tampered cookies produce no session, no error, and no cookie changes. Only a successful verification reissues the cookie and only `delete` clears it.
- Successful verification reissues the exact presented token with a fresh `Max-Age`, so the browser and server expiry slide together while a session stays in use.

## Expiry semantics

`validityToken` is a sliding inactivity window. The storage records the time of the last successful verification; a session expires when that time plus `validityToken` is reached, equality included. An expired session's record is removed at the next verification attempt, freeing its ID for reuse.

Each successful verification reissues the cookie with `Max-Age` derived from `validityToken`, so server and browser expiry slide together as long as the session stays in use. An idle session eventually expires on both sides.

## Concurrent tabs

All tabs of an application share one cookie and therefore one session. Interleaved reads and writes from multiple tabs work against the same record. No per-user session map, no request ordering, and no client-side coordination are involved.

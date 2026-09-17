import test from 'ava';
import { Hono } from 'hono';
import { SessionsManager, SessionsStorage } from '../../dist/index.js';
import * as packageModule from '../../dist/index.js';
import { assertNoSetCookie, base64UrlDecode, base64UrlEncode, cookiePairFrom, createTestApp, jsonResponse, tokenFromSetCookie } from './TestHelpers.js';
const ivLength = 12;
const key16 = keyFromLength(16);
const key24 = keyFromLength(24);
const key32 = keyFromLength(32);
const secretTextOther = base64UrlEncode(new Uint8Array(32).fill(7));
const base64UrlAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
class AsyncSessionsStorage {
    _inner;
    constructor() {
        this._inner = new SessionsStorage.Local();
    }
    async create(secret, validityToken) {
        return this._inner.create(secret, validityToken);
    }
    async verify(sessionId, secret, validityToken) {
        return this._inner.verify(sessionId, secret, validityToken);
    }
    async delete(sessionId, secret) {
        return this._inner.delete(sessionId, secret);
    }
}
class CountingVerifyStorage {
    _inner;
    verifyCalls;
    constructor() {
        this._inner = new SessionsStorage.Local();
        this.verifyCalls = 0;
    }
    create(secret, validityToken) {
        return this._inner.create(secret, validityToken);
    }
    verify(sessionId, secret, validityToken) {
        this.verifyCalls++;
        return this._inner.verify(sessionId, secret, validityToken);
    }
    delete(sessionId, secret) {
        return this._inner.delete(sessionId, secret);
    }
}
class ThrowingDeleteStorage {
    _inner;
    constructor() {
        this._inner = new SessionsStorage.Local();
    }
    create(secret, validityToken) {
        return this._inner.create(secret, validityToken);
    }
    verify(sessionId, secret, validityToken) {
        return this._inner.verify(sessionId, secret, validityToken);
    }
    delete(_sessionId, _secret) {
        throw new Error('Storage unavailable');
    }
}
class ThrowingVerifyStorage {
    _inner;
    constructor() {
        this._inner = new SessionsStorage.Local();
    }
    create(secret, validityToken) {
        return this._inner.create(secret, validityToken);
    }
    verify(_sessionId, _secret, _validityToken) {
        throw new Error('Storage unavailable');
    }
    delete(sessionId, secret) {
        return this._inner.delete(sessionId, secret);
    }
}
function keyFromLength(length) {
    const returnValue = new Uint8Array(length);
    for (let iL1 = 0; iL1 < length; iL1++) {
        returnValue[iL1] = (iL1 + 1) & 0xff;
    }
    return returnValue;
}
function fakeClockAt(start) {
    const realDateNow = Date.now;
    let current = start;
    Date.now = () => current;
    const returnValue = {
        advance(milliseconds) {
            current += milliseconds;
        },
        restore() {
            Date.now = realDateNow;
        }
    };
    return returnValue;
}
function cookieHeader(token, cookieName = 'session') {
    return `${cookieName}=${token}`;
}
async function createSessionToken(app) {
    const response = await app.request('/create', { method: 'POST' });
    const header = response.headers.get('set-cookie');
    let returnValue;
    if (header) {
        returnValue = tokenFromSetCookie(header);
    }
    else {
        throw new Error('Creation did not set a cookie');
    }
    return returnValue;
}
async function verifyResponse(app, token, cookieName = 'session') {
    const returnValue = await app.request('/verify', { headers: { cookie: cookieHeader(token, cookieName) } });
    return returnValue;
}
async function isAuthenticated(app, token, cookieName = 'session') {
    const response = await verifyResponse(app, token, cookieName);
    const payload = await jsonResponse(response);
    return payload.authenticated;
}
async function credentialFromToken(token, keyBytes) {
    const importedKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const bytes = base64UrlDecode(token);
    const iv = bytes.slice(0, ivLength);
    const ciphertext = bytes.slice(ivLength);
    const params = {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 64
    };
    const plaintext = await crypto.subtle.decrypt(params, importedKey, ciphertext);
    const tuple = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    let returnValue;
    if (Array.isArray(tuple) && (2 === tuple.length) && ('number' === typeof tuple[0]) && ('string' === typeof tuple[1])) {
        returnValue = { secretText: tuple[1], sessionId: tuple[0] };
    }
    else {
        throw new Error('Malformed credential');
    }
    return returnValue;
}
async function encryptToken(keyBytes, plaintext) {
    const importedKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = new Uint8Array(ivLength);
    crypto.getRandomValues(iv);
    const encoded = new TextEncoder().encode(plaintext);
    const params = {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 64
    };
    const encrypted = await crypto.subtle.encrypt(params, importedKey, encoded);
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    const returnValue = base64UrlEncode(combined);
    return returnValue;
}
function flippedToken(token, index) {
    const characters = token.split('');
    characters[index] = ('A' === characters[index]) ? 'B' : 'A';
    const returnValue = characters.join('');
    return returnValue;
}
function nonCanonicalVariants(text) {
    const bytes = base64UrlDecode(text);
    const remainder = bytes.length % 3;
    const variants = [];
    if (0 !== remainder) {
        const unusedBits = (1 === remainder) ? 4 : 2;
        const variantCount = (1 << unusedBits) - 1;
        const lastIndex = base64UrlAlphabet.indexOf(text.charAt(text.length - 1));
        for (let iL1 = 1; iL1 <= variantCount; iL1++) {
            variants.push(text.slice(0, text.length - 1) + base64UrlAlphabet.charAt(lastIndex + iL1));
        }
    }
    return variants;
}
function sabotageEncrypt() {
    return overrideSubtle((sabotaged) => {
        sabotaged.encrypt = () => Promise.reject(new Error('Encryption unavailable'));
    });
}
function overrideSubtle(override) {
    const originalSubtle = crypto.subtle;
    const ownDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    const sabotagedSubtle = Object.create(originalSubtle);
    // Native Web Crypto methods brand-check their receiver, so every method the factory touches must delegate to the original instance.
    sabotagedSubtle.encrypt = (...args) => originalSubtle.encrypt(...args);
    sabotagedSubtle.decrypt = (...args) => originalSubtle.decrypt(...args);
    sabotagedSubtle.importKey = (...args) => originalSubtle.importKey(...args);
    sabotagedSubtle.generateKey = (algorithm, extractable, keyUsages) => originalSubtle.generateKey(algorithm, extractable, keyUsages);
    override(sabotagedSubtle, originalSubtle);
    Object.defineProperty(crypto, 'subtle', { value: sabotagedSubtle, configurable: true });
    const returnValue = {
        restore() {
            if (ownDescriptor) {
                Object.defineProperty(crypto, 'subtle', ownDescriptor);
            }
            else {
                Reflect.deleteProperty(crypto, 'subtle');
            }
        }
    };
    return returnValue;
}
test('base64url helper produces canonical vectors', (t) => {
    t.is(base64UrlEncode(new TextEncoder().encode('foobar')), 'Zm9vYmFy');
    t.is(base64UrlEncode(new Uint8Array(0)), '');
    t.is(base64UrlEncode(new Uint8Array([251, 255])), '-_8');
    const roundTrip = base64UrlDecode('-_8');
    t.is(roundTrip.length, 2);
    t.is(roundTrip[0], 251);
    t.is(roundTrip[1], 255);
});
test('default creation sets the session cookie with canonical defaults', async (t) => {
    const manager = await SessionsManager.create();
    const app = createTestApp(manager);
    const response = await app.request('/create', { method: 'POST' });
    const headers = response.headers.getSetCookie();
    t.is(headers.length, 1);
    const header = headers[0];
    const pair = cookiePairFrom(header);
    t.true(pair.startsWith('session='));
    const token = tokenFromSetCookie(header);
    t.regex(token, /^[A-Za-z0-9_-]+$/);
    t.false(token.includes('='));
    t.true(header.includes('HttpOnly'));
    t.true(header.includes('Secure'));
    t.true(header.includes('SameSite=Lax'));
    t.true(header.includes('Path=/'));
    t.true(header.includes('Max-Age=3600'));
    t.false(header.includes('Domain='));
    t.false(header.includes('Partitioned'));
    t.false(header.includes('Priority='));
    t.false(header.includes('Expires='));
});
test('cookie token decrypts externally to the credential tuple', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const bytes = base64UrlDecode(token);
    t.true(ivLength < bytes.length);
    const iv = bytes.slice(0, ivLength);
    const ciphertext = bytes.slice(ivLength);
    const importedKey = await crypto.subtle.importKey('raw', key16, { name: 'AES-GCM' }, false, ['decrypt']);
    const params = {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 64
    };
    const plaintext = await crypto.subtle.decrypt(params, importedKey, ciphertext);
    const json = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    t.regex(json, /^\[\d+,"[A-Za-z0-9_-]+"\]$/);
    const tuple = JSON.parse(json);
    if (Array.isArray(tuple) && (2 === tuple.length) && ('number' === typeof tuple[0]) && ('string' === typeof tuple[1])) {
        const secret = base64UrlDecode(tuple[1]);
        t.is(secret.length, 32);
    }
    else {
        t.fail('Credential tuple shape mismatch');
    }
});
test('a successful round trip renews the exact token cookie with default attributes', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const response = await verifyResponse(app, token);
    const payload = await jsonResponse(response);
    t.true(payload.authenticated);
    const headers = response.headers.getSetCookie();
    t.is(headers.length, 1);
    const renewal = headers[0];
    t.is(tokenFromSetCookie(renewal), token);
    t.true(renewal.includes('HttpOnly'));
    t.true(renewal.includes('Secure'));
    t.true(renewal.includes('SameSite=Lax'));
    t.true(renewal.includes('Path=/'));
    t.true(renewal.includes('Max-Age=3600'));
});
test('malformed client tokens yield no session and clear nothing', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const validToken = await createSessionToken(app);
    const randomBytes = new Uint8Array(40);
    crypto.getRandomValues(randomBytes);
    const malformedTokens = [
        '',
        'abc$def',
        'Zm9vYmFy==',
        'A',
        'AAAAA',
        validToken.slice(0, validToken.length - 5),
        base64UrlEncode(randomBytes),
        await encryptToken(key16, 'not json'),
        await encryptToken(key16, '["one","two"]'),
        await encryptToken(key16, '{"a":1}'),
        await encryptToken(key16, '[0]'),
        await encryptToken(key16, `[0,"${base64UrlEncode(new Uint8Array(16).fill(3))}"]`)
    ];
    const cL1 = malformedTokens.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const malformed = malformedTokens[iL1];
        const response = await verifyResponse(app, malformed);
        const payload = await jsonResponse(response);
        t.false(payload.authenticated);
        assertNoSetCookie(t, response);
    }
    const missing = await app.request('/verify');
    const missingPayload = await jsonResponse(missing);
    t.false(missingPayload.authenticated);
    assertNoSetCookie(t, missing);
});
test('altered iv or ciphertext fails authentication without clearing the cookie', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const alteredTokens = [
        flippedToken(token, 0),
        flippedToken(token, Math.floor(token.length / 2)),
        flippedToken(token, token.length - 1)
    ];
    const cL1 = alteredTokens.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const altered = alteredTokens[iL1];
        t.false(await isAuthenticated(app, altered));
        assertNoSetCookie(t, await verifyResponse(app, altered));
    }
});
test('non-canonical byte-equivalent outer tokens are accepted', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const sessionCount = 11;
    let token = '';
    for (let iL1 = 0; iL1 < sessionCount; iL1++) {
        token = await createSessionToken(app);
    }
    const variants = nonCanonicalVariants(token);
    t.true(variants.length > 0);
    t.true(await isAuthenticated(app, token));
    const cL1 = variants.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const variant = variants[iL1];
        const response = await verifyResponse(app, variant);
        const payload = await jsonResponse(response);
        t.true(payload.authenticated);
        const renewalHeaders = response.headers.getSetCookie();
        t.is(renewalHeaders.length, 1);
        t.is(tokenFromSetCookie(renewalHeaders[0]), variant);
        t.true(renewalHeaders[0].includes('Max-Age=3600'));
    }
});
test('non-canonical byte-equivalent embedded secrets are accepted', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const credential = await credentialFromToken(token, key16);
    const variants = nonCanonicalVariants(credential.secretText);
    t.true(variants.length > 0);
    const cL1 = variants.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const variant = variants[iL1];
        const forged = await encryptToken(key16, JSON.stringify([credential.sessionId, variant]));
        const response = await verifyResponse(app, forged);
        const payload = await jsonResponse(response);
        t.true(payload.authenticated);
        const renewalHeaders = response.headers.getSetCookie();
        t.is(renewalHeaders.length, 1);
        t.is(tokenFromSetCookie(renewalHeaders[0]), forged);
    }
    t.true(await isAuthenticated(app, token));
});
test('a whitespace-wrapped credential plaintext yields no session without storage verification', async (t) => {
    const storage = new CountingVerifyStorage();
    const manager = await SessionsManager.create({ encryptionKey: key16, storage });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const credential = await credentialFromToken(token, key16);
    const forged = await encryptToken(key16, `[ ${credential.sessionId},"${credential.secretText}" ]`);
    const verifyCallsBefore = storage.verifyCalls;
    const response = await verifyResponse(app, forged);
    const payload = await jsonResponse(response);
    t.false(payload.authenticated);
    assertNoSetCookie(t, response);
    t.is(storage.verifyCalls, verifyCallsBefore);
});
test('a leading UTF-8 BOM in the credential plaintext yields no session without storage verification', async (t) => {
    const storage = new CountingVerifyStorage();
    const manager = await SessionsManager.create({ encryptionKey: key16, storage });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const credential = await credentialFromToken(token, key16);
    const forged = await encryptToken(key16, '\uFEFF' + JSON.stringify([credential.sessionId, credential.secretText]));
    const verifyCallsBefore = storage.verifyCalls;
    const response = await verifyResponse(app, forged);
    const payload = await jsonResponse(response);
    t.false(payload.authenticated);
    assertNoSetCookie(t, response);
    t.is(storage.verifyCalls, verifyCallsBefore);
});
test('an alternate numeric spelling of the session id yields no session without storage verification', async (t) => {
    const storage = new CountingVerifyStorage();
    const manager = await SessionsManager.create({ encryptionKey: key16, storage });
    const app = createTestApp(manager);
    await createSessionToken(app);
    const token = await createSessionToken(app);
    const credential = await credentialFromToken(token, key16);
    t.is(credential.sessionId, 1);
    const forged = await encryptToken(key16, `[1e0,"${credential.secretText}"]`);
    const verifyCallsBefore = storage.verifyCalls;
    const response = await verifyResponse(app, forged);
    const payload = await jsonResponse(response);
    t.false(payload.authenticated);
    assertNoSetCookie(t, response);
    t.is(storage.verifyCalls, verifyCallsBefore);
});
test('credential session IDs outside the storage contract are rejected before storage verification', async (t) => {
    const storage = new CountingVerifyStorage();
    const manager = await SessionsManager.create({ encryptionKey: key16, storage });
    const app = createTestApp(manager);
    const invalidSessionIds = [-1, 1.5, Number.MAX_SAFE_INTEGER + 1];
    const verifyCallsBefore = storage.verifyCalls;
    const cL1 = invalidSessionIds.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const invalidSessionId = invalidSessionIds[iL1];
        const token = await encryptToken(key16, JSON.stringify([invalidSessionId, secretTextOther]));
        const response = await verifyResponse(app, token);
        const payload = await jsonResponse(response);
        t.false(payload.authenticated);
        assertNoSetCookie(t, response);
    }
    t.is(storage.verifyCalls, verifyCallsBefore);
});
test('a wrong stored secret verifies to nothing and leaves the record intact', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const credential = await credentialFromToken(token, key16);
    const forged = await encryptToken(key16, JSON.stringify([credential.sessionId, secretTextOther]));
    const forgedResponse = await verifyResponse(app, forged);
    const forgedPayload = await jsonResponse(forgedResponse);
    t.false(forgedPayload.authenticated);
    assertNoSetCookie(t, forgedResponse);
    t.true(await isAuthenticated(app, token));
});
test.serial('at exact deadline verification returns no session and deletes the record', async (t) => {
    const clock = fakeClockAt(1_000);
    try {
        const manager = await SessionsManager.create({ encryptionKey: key16, validityToken: 100 });
        const app = createTestApp(manager);
        const firstToken = await createSessionToken(app);
        const firstCredential = await credentialFromToken(firstToken, key16);
        clock.advance(100);
        const expiredResponse = await verifyResponse(app, firstToken);
        const expiredPayload = await jsonResponse(expiredResponse);
        t.false(expiredPayload.authenticated);
        assertNoSetCookie(t, expiredResponse);
        const secondToken = await createSessionToken(app);
        const secondCredential = await credentialFromToken(secondToken, key16);
        t.is(secondCredential.sessionId, firstCredential.sessionId);
    }
    finally {
        clock.restore();
    }
});
test.serial('successful verification slides expiry past the original deadline', async (t) => {
    const clock = fakeClockAt(1_000);
    try {
        const manager = await SessionsManager.create({ encryptionKey: key16, validityToken: 100 });
        const app = createTestApp(manager);
        const token = await createSessionToken(app);
        clock.advance(50);
        t.true(await isAuthenticated(app, token));
        const renewal = await verifyResponse(app, token);
        const renewalHeaders = renewal.headers.getSetCookie();
        t.is(renewalHeaders.length, 1);
        t.true(renewalHeaders[0].includes('Max-Age=1'));
        clock.advance(60);
        t.true(await isAuthenticated(app, token));
        clock.advance(100);
        t.false(await isAuthenticated(app, token));
    }
    finally {
        clock.restore();
    }
});
test('logout removes the session and clears the cookie and context session', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const logout = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(token) } });
    const payload = await jsonResponse(logout);
    t.true(payload.deleted);
    t.true(payload.cleared);
    const headers = logout.headers.getSetCookie();
    t.is(headers.length, 2);
    const renewal = headers[0];
    const deletion = headers[1];
    t.is(tokenFromSetCookie(renewal), token);
    t.true(renewal.includes('Max-Age=3600'));
    t.true(cookiePairFrom(deletion).startsWith('session='));
    t.true(deletion.includes('Max-Age=0'));
    t.false(await isAuthenticated(app, token));
});
test('logout with a malformed token still clears the cookie', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    await createSessionToken(app);
    const logout = await app.request('/logout', { method: 'POST', headers: { cookie: 'session=###bad' } });
    const payload = await jsonResponse(logout);
    t.false(payload.deleted);
    t.true(payload.cleared);
    const headers = logout.headers.getSetCookie();
    t.is(headers.length, 1);
    t.true(headers[0].includes('Max-Age=0'));
});
test('create after a valid cookie renews the old token first and issues a new token last', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const oldToken = await createSessionToken(app);
    const response = await app.request('/create', { method: 'POST', headers: { cookie: cookieHeader(oldToken) } });
    const headers = response.headers.getSetCookie();
    t.is(headers.length, 2);
    const renewal = headers[0];
    const created = headers[1];
    t.is(tokenFromSetCookie(renewal), oldToken);
    t.true(renewal.includes('Max-Age=3600'));
    t.not(tokenFromSetCookie(created), oldToken);
    t.true(created.includes('Max-Age=3600'));
});
test('storage deletion failure propagates without a removal cookie', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16, storage: new ThrowingDeleteStorage() });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const captureApp = new Hono();
    let captured;
    captureApp.get('/capture', (context) => {
        captured = context;
        return context.text('ok');
    });
    await captureApp.request('/capture');
    if (captured) {
        const capturedContext = captured;
        await t.throwsAsync(() => manager.delete(capturedContext, token), { message: 'Storage unavailable' });
        t.is(capturedContext.res.headers.get('set-cookie'), null);
    }
    else {
        t.fail('Context capture failed');
    }
});
test('direct verify renews the token cookie and a later malformed verify adds nothing', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const captureApp = new Hono();
    let captured;
    captureApp.get('/capture', (context) => {
        captured = context;
        return context.text('ok');
    });
    await captureApp.request('/capture');
    if (captured) {
        const capturedContext = captured;
        const session = await manager.verify(capturedContext, token);
        if (session) {
            t.is(capturedContext.get('session'), session);
            const renewalHeaders = capturedContext.res.headers.getSetCookie();
            t.is(renewalHeaders.length, 1);
            t.is(tokenFromSetCookie(renewalHeaders[0]), token);
            const malformed = await manager.verify(capturedContext, '###bad');
            t.is(malformed, undefined);
            t.is(capturedContext.get('session'), undefined);
            t.is(capturedContext.res.headers.getSetCookie().length, 1);
        }
        else {
            t.fail('Valid verification must return a session');
        }
    }
    else {
        t.fail('Context capture failed');
    }
});
test('storage verification failure propagates without setting a cookie', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16, storage: new ThrowingVerifyStorage() });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const captureApp = new Hono();
    let captured;
    captureApp.get('/capture', (context) => {
        captured = context;
        return context.text('ok');
    });
    await captureApp.request('/capture');
    if (captured) {
        const capturedContext = captured;
        await t.throwsAsync(() => manager.verify(capturedContext, token), { message: 'Storage unavailable' });
        t.is(capturedContext.get('session'), undefined);
        t.is(capturedContext.res.headers.get('set-cookie'), null);
    }
    else {
        t.fail('Context capture failed');
    }
});
test('renewal serialization failure propagates without a session or header', async (t) => {
    const storage = new SessionsStorage.Local();
    const issuer = await SessionsManager.create({ encryptionKey: key16, storage });
    const issuerApp = createTestApp(issuer);
    const token = await createSessionToken(issuerApp);
    const verifier = await SessionsManager.create({ cookie: { path: '/bad;path' }, encryptionKey: key16, storage });
    const captureApp = new Hono();
    let captured;
    captureApp.get('/capture', (context) => {
        captured = context;
        return context.text('ok');
    });
    await captureApp.request('/capture');
    if (captured) {
        const capturedContext = captured;
        await t.throwsAsync(() => verifier.verify(capturedContext, token), { message: 'path must not contain ";", "\\r", or "\\n"' });
        t.is(capturedContext.get('session'), undefined);
        t.is(capturedContext.res.headers.getSetCookie().length, 0);
    }
    else {
        t.fail('Context capture failed');
    }
});
test('id reuse with maxSessions one invalidates the old credential', async (t) => {
    const storage = new SessionsStorage.Local();
    const manager = await SessionsManager.create({ encryptionKey: key16, storage });
    const app = createTestApp(manager);
    const firstToken = await createSessionToken(app);
    const firstCredential = await credentialFromToken(firstToken, key16);
    const logoutFirst = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(firstToken) } });
    const firstPayload = await jsonResponse(logoutFirst);
    t.true(firstPayload.deleted);
    const secondToken = await createSessionToken(app);
    const secondCredential = await credentialFromToken(secondToken, key16);
    t.is(secondCredential.sessionId, firstCredential.sessionId);
    const invalidatedResponse = await verifyResponse(app, firstToken);
    const invalidatedPayload = await jsonResponse(invalidatedResponse);
    t.false(invalidatedPayload.authenticated);
    assertNoSetCookie(t, invalidatedResponse);
    t.true(await isAuthenticated(app, secondToken));
    const forgedLogout = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(firstToken) } });
    const forgedPayload = await jsonResponse(forgedLogout);
    t.false(forgedPayload.deleted);
    t.true(forgedPayload.cleared);
    const logoutSecond = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(secondToken) } });
    const secondPayload = await jsonResponse(logoutSecond);
    t.true(secondPayload.deleted);
    t.true(secondPayload.cleared);
});
test('ten concurrent requests with one token all authenticate', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const requests = [];
    for (let iL1 = 0; iL1 < 10; iL1++) {
        requests.push(isAuthenticated(app, token));
    }
    const results = await Promise.all(requests);
    t.deepEqual(results, [true, true, true, true, true, true, true, true, true, true]);
});
test('two conceptual tabs interleave data operations on one session', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    const header = { 'content-type': 'application/json', cookie: cookieHeader(token) };
    const writes = [
        Promise.resolve(app.request('/set/tab', { method: 'POST', headers: header, body: JSON.stringify({ tab: 1 }) })),
        Promise.resolve(app.request('/set/note', { method: 'POST', headers: header, body: JSON.stringify('hello') })),
        Promise.resolve(app.request('/get/tab', { headers: { cookie: cookieHeader(token) } })),
        Promise.resolve(app.request('/verify', { headers: { cookie: cookieHeader(token) } }))
    ];
    const settled = await Promise.all(writes);
    const cL1 = settled.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const settledResponse = settled[iL1];
        t.true(settledResponse.ok);
    }
    const readTab = await app.request('/get/tab', { headers: { cookie: cookieHeader(token) } });
    const tabPayload = await jsonResponse(readTab);
    t.deepEqual(tabPayload.value, { tab: 1 });
    const readNote = await app.request('/get/note', { headers: { cookie: cookieHeader(token) } });
    const notePayload = await jsonResponse(readNote);
    t.is(notePayload.value, 'hello');
});
test('async custom storage drives the same flow', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16, storage: new AsyncSessionsStorage() });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    t.true(await isAuthenticated(app, token));
    await app.request('/set/marker', { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(token) }, body: JSON.stringify('ok') });
    const read = await app.request('/get/marker', { headers: { cookie: cookieHeader(token) } });
    const payload = await jsonResponse(read);
    t.is(payload.value, 'ok');
    const logout = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(token) } });
    const logoutPayload = await jsonResponse(logout);
    t.true(logoutPayload.deleted);
    t.true(logoutPayload.cleared);
});
test('separate generated keys cannot cross verify and keep working alone', async (t) => {
    const first = await SessionsManager.create();
    const second = await SessionsManager.create();
    const firstApp = createTestApp(first);
    const secondApp = createTestApp(second);
    const token = await createSessionToken(firstApp);
    t.false(await isAuthenticated(secondApp, token));
    t.true(await isAuthenticated(firstApp, token));
});
test('the same supplied key and storage interoperate', async (t) => {
    const storage = new SessionsStorage.Local();
    const first = await SessionsManager.create({ encryptionKey: key16, storage });
    const second = await SessionsManager.create({ encryptionKey: key16, storage });
    const firstApp = createTestApp(first);
    const secondApp = createTestApp(second);
    const token = await createSessionToken(firstApp);
    t.true(await isAuthenticated(secondApp, token));
});
test('a custom cookie name drives creation, lookup, renewal, and deletion', async (t) => {
    const cookieName = 'app.sid';
    const manager = await SessionsManager.create({ cookie: { name: cookieName }, encryptionKey: key16 });
    const app = createTestApp(manager, cookieName);
    const created = await app.request('/create', { method: 'POST' });
    const createdHeaders = created.headers.getSetCookie();
    t.is(createdHeaders.length, 1);
    const createdHeader = createdHeaders[0];
    t.true(cookiePairFrom(createdHeader).startsWith('app.sid='));
    const token = tokenFromSetCookie(createdHeader);
    const renewed = await verifyResponse(app, token, cookieName);
    const renewedPayload = await jsonResponse(renewed);
    t.true(renewedPayload.authenticated);
    const renewedHeaders = renewed.headers.getSetCookie();
    t.is(renewedHeaders.length, 1);
    const renewal = renewedHeaders[0];
    t.is(tokenFromSetCookie(renewal), token);
    t.true(cookiePairFrom(renewal).startsWith('app.sid='));
    const logout = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(token, cookieName) } });
    const logoutPayload = await jsonResponse(logout);
    t.true(logoutPayload.deleted);
    t.true(logoutPayload.cleared);
    const logoutHeaders = logout.headers.getSetCookie();
    t.is(logoutHeaders.length, 2);
    const logoutRenewal = logoutHeaders[0];
    const deletion = logoutHeaders[1];
    t.is(tokenFromSetCookie(logoutRenewal), token);
    t.true(cookiePairFrom(logoutRenewal).startsWith('app.sid='));
    t.true(cookiePairFrom(deletion).startsWith('app.sid='));
    t.true(deletion.includes('Max-Age=0'));
    const afterLogout = await verifyResponse(app, token, cookieName);
    const afterLogoutPayload = await jsonResponse(afterLogout);
    t.false(afterLogoutPayload.authenticated);
    assertNoSetCookie(t, afterLogout);
});
test('a custom-named manager ignores its token under the default cookie name', async (t) => {
    const cookieName = 'app.sid';
    const manager = await SessionsManager.create({ cookie: { name: cookieName }, encryptionKey: key16 });
    const app = createTestApp(manager, cookieName);
    const token = await createSessionToken(app);
    const response = await verifyResponse(app, token);
    const payload = await jsonResponse(response);
    t.false(payload.authenticated);
    assertNoSetCookie(t, response);
});
test('managers with different cookie names read only their configured name', async (t) => {
    const storage = new SessionsStorage.Local();
    const first = await SessionsManager.create({ cookie: { name: 'first.sid' }, encryptionKey: key16, storage });
    const second = await SessionsManager.create({ cookie: { name: 'second.sid' }, encryptionKey: key16, storage });
    const firstApp = createTestApp(first, 'first.sid');
    const secondApp = createTestApp(second, 'second.sid');
    const token = await createSessionToken(firstApp);
    // Cookie-name isolation is lookup isolation, not cryptographic isolation: the shared key and storage let the second manager read the token once it arrives under the second name.
    const underFirst = await verifyResponse(secondApp, token, 'first.sid');
    const underFirstPayload = await jsonResponse(underFirst);
    t.false(underFirstPayload.authenticated);
    assertNoSetCookie(t, underFirst);
    const underSecond = await verifyResponse(secondApp, token, 'second.sid');
    const underSecondPayload = await jsonResponse(underSecond);
    t.true(underSecondPayload.authenticated);
    const renewalHeaders = underSecond.headers.getSetCookie();
    t.is(renewalHeaders.length, 1);
    const renewal = renewalHeaders[0];
    t.is(tokenFromSetCookie(renewal), token);
    t.true(cookiePairFrom(renewal).startsWith('second.sid='));
});
test('a 32-byte supplied key creates and verifies a session without algorithm configuration', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key32 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    t.true(await isAuthenticated(app, token));
    const credential = await credentialFromToken(token, key32);
    t.true(Number.isSafeInteger(credential.sessionId));
    t.true(0 <= credential.sessionId);
});
test('a 24-byte supplied key creates and verifies a session without algorithm configuration', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key24 });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    t.true(await isAuthenticated(app, token));
    const credential = await credentialFromToken(token, key24);
    t.true(Number.isSafeInteger(credential.sessionId));
    t.true(0 <= credential.sessionId);
});
test.serial('creation generates exactly one AES-128 key and reuses it for the manager lifetime', async (t) => {
    const generateCalls = [];
    const sabotage = overrideSubtle((sabotaged, original) => {
        sabotaged.generateKey = (algorithm, extractable, keyUsages) => {
            generateCalls.push({ algorithm, extractable, keyUsages });
            return original.generateKey(algorithm, extractable, keyUsages);
        };
    });
    try {
        const manager = await SessionsManager.create();
        t.deepEqual(generateCalls, [{ algorithm: { name: 'AES-GCM', length: 128 }, extractable: false, keyUsages: ['encrypt', 'decrypt'] }]);
        const app = createTestApp(manager);
        const firstToken = await createSessionToken(app);
        t.true(await isAuthenticated(app, firstToken));
        const secondToken = await createSessionToken(app);
        t.true(await isAuthenticated(app, secondToken));
        t.is(generateCalls.length, 1);
    }
    finally {
        sabotage.restore();
    }
});
test('invalid key length rejects the factory', async (t) => {
    const shortKey = keyFromLength(15);
    await t.throwsAsync(SessionsManager.create({ encryptionKey: shortKey }));
});
test('cookie modes map to the canonical SameSite and Partitioned attributes', async (t) => {
    const cases = [
        { mode: 'strict', partitioned: false, sameSite: 'SameSite=Strict' },
        { mode: 'lax', partitioned: false, sameSite: 'SameSite=Lax' },
        { mode: 'cross-site', partitioned: false, sameSite: 'SameSite=None' },
        { mode: 'partitioned', partitioned: true, sameSite: 'SameSite=None' }
    ];
    const cL1 = cases.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const cookieCase = cases[iL1];
        const manager = await SessionsManager.create({ cookie: { mode: cookieCase.mode }, encryptionKey: key16 });
        const app = createTestApp(manager);
        const response = await app.request('/create', { method: 'POST' });
        const headers = response.headers.getSetCookie();
        t.is(headers.length, 1);
        const header = headers[0];
        t.true(header.includes(cookieCase.sameSite));
        t.is(header.includes('Partitioned'), cookieCase.partitioned);
        t.true(header.includes('Secure'));
        t.true(header.includes('HttpOnly'));
    }
});
test('partitioned cookies keep their attributes on creation, renewal, and deletion', async (t) => {
    const manager = await SessionsManager.create({ cookie: { domain: 'example.com', mode: 'partitioned', path: '/auth' }, encryptionKey: key16 });
    const app = createTestApp(manager);
    const created = await app.request('/create', { method: 'POST' });
    const createdHeaders = created.headers.getSetCookie();
    t.is(createdHeaders.length, 1);
    const createdHeader = createdHeaders[0];
    t.true(createdHeader.includes('Partitioned'));
    t.true(createdHeader.includes('SameSite=None'));
    t.true(createdHeader.includes('Secure'));
    t.true(createdHeader.includes('Domain=example.com'));
    t.true(createdHeader.includes('Path=/auth'));
    const token = tokenFromSetCookie(createdHeader);
    const logout = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(token) } });
    const logoutHeaders = logout.headers.getSetCookie();
    t.is(logoutHeaders.length, 2);
    const renewal = logoutHeaders[0];
    t.is(tokenFromSetCookie(renewal), token);
    t.true(renewal.includes('HttpOnly'));
    t.true(renewal.includes('SameSite=None'));
    t.true(renewal.includes('Partitioned'));
    t.true(renewal.includes('Secure'));
    t.true(renewal.includes('Domain=example.com'));
    t.true(renewal.includes('Path=/auth'));
    t.true(renewal.includes('Max-Age=3600'));
    t.false(renewal.includes('Expires='));
    const deletion = logoutHeaders[1];
    t.true(deletion.includes('Partitioned'));
    t.true(deletion.includes('SameSite=None'));
    t.true(deletion.includes('Secure'));
    t.true(deletion.includes('Domain=example.com'));
    t.true(deletion.includes('Path=/auth'));
    t.true(deletion.includes('Max-Age=0'));
});
test('cookie options set to undefined keep the canonical defaults', async (t) => {
    const manager = await SessionsManager.create({ cookie: { domain: undefined, mode: undefined, name: undefined, path: undefined, secure: undefined }, encryptionKey: key16 });
    const app = createTestApp(manager);
    const response = await app.request('/create', { method: 'POST' });
    const headers = response.headers.getSetCookie();
    t.is(headers.length, 1);
    const header = headers[0];
    t.true(cookiePairFrom(header).startsWith('session='));
    t.true(header.includes('HttpOnly'));
    t.true(header.includes('Secure'));
    t.true(header.includes('SameSite=Lax'));
    t.true(header.includes('Path=/'));
    t.true(header.includes('Max-Age=3600'));
    t.false(header.includes('Domain='));
    t.false(header.includes('Partitioned'));
});
test('secure false is allowed for strict and lax and keeps HttpOnly without Secure', async (t) => {
    const modes = ['strict', 'lax'];
    const cL1 = modes.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const mode = modes[iL1];
        const manager = await SessionsManager.create({ cookie: { mode, secure: false }, encryptionKey: key16 });
        const app = createTestApp(manager);
        const response = await app.request('/create', { method: 'POST' });
        const headers = response.headers.getSetCookie();
        t.is(headers.length, 1);
        const header = headers[0];
        t.false(header.includes('Secure'));
        t.true(header.includes('HttpOnly'));
        t.true(header.includes('Path=/'));
        t.true(header.includes('Max-Age=3600'));
    }
});
test('the supplied key is copied before import', async (t) => {
    const keyBytes = keyFromLength(16);
    const manager = await SessionsManager.create({ encryptionKey: keyBytes });
    const app = createTestApp(manager);
    const token = await createSessionToken(app);
    keyBytes.fill(0);
    t.true(await isAuthenticated(app, token));
});
test.serial('an issuance failure cleans up the created record', async (t) => {
    const storage = new SessionsStorage.Local();
    const brokenManager = await SessionsManager.create({ encryptionKey: key16, storage });
    const captureApp = new Hono();
    let captured;
    captureApp.get('/capture', (context) => {
        captured = context;
        return context.text('ok');
    });
    await captureApp.request('/capture');
    if (captured) {
        const capturedContext = captured;
        const sabotage = sabotageEncrypt();
        try {
            await t.throwsAsync(() => brokenManager.create(capturedContext), { message: 'Encryption unavailable' });
        }
        finally {
            sabotage.restore();
        }
        t.is(capturedContext.res.headers.get('set-cookie'), null);
        const healthyManager = await SessionsManager.create({ encryptionKey: key16, storage });
        const healthyApp = createTestApp(healthyManager);
        const token = await createSessionToken(healthyApp);
        const credential = await credentialFromToken(token, key16);
        t.is(credential.sessionId, 0);
    }
    else {
        t.fail('Context capture failed');
    }
});
test.serial('an issuance failure still rethrows its own error when cleanup also fails', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16, storage: new ThrowingDeleteStorage() });
    const captureApp = new Hono();
    let captured;
    captureApp.get('/capture', (context) => {
        captured = context;
        return context.text('ok');
    });
    await captureApp.request('/capture');
    if (captured) {
        const capturedContext = captured;
        const sabotage = sabotageEncrypt();
        try {
            await t.throwsAsync(() => manager.create(capturedContext), { message: 'Encryption unavailable' });
        }
        finally {
            sabotage.restore();
        }
        t.is(capturedContext.res.headers.get('set-cookie'), null);
    }
    else {
        t.fail('Context capture failed');
    }
});
test('tokens that decode to a short buffer yield no session', async (t) => {
    const manager = await SessionsManager.create({ encryptionKey: key16 });
    const app = createTestApp(manager);
    const shortTokens = [
        base64UrlEncode(new Uint8Array(12)),
        base64UrlEncode(new Uint8Array(4))
    ];
    const cL1 = shortTokens.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const short = shortTokens[iL1];
        t.false(await isAuthenticated(app, short));
        assertNoSetCookie(t, await verifyResponse(app, short));
    }
});
test('invalid validityToken rejects the factory', async (t) => {
    await t.throwsAsync(SessionsManager.create({ validityToken: 0 }), { message: 'validityToken must be a positive safe integer' });
    await t.throwsAsync(SessionsManager.create({ validityToken: 1.5 }), { message: 'validityToken must be a positive safe integer' });
});
test('invalid cookie paths reject the factory', async (t) => {
    const expectedMessage = 'cookie.path must be a non-empty absolute path starting with /';
    await t.throwsAsync(SessionsManager.create({ cookie: { path: '' } }), { message: expectedMessage });
    await t.throwsAsync(SessionsManager.create({ cookie: { path: 'auth' } }), { message: expectedMessage });
});
test('invalid cookie names reject the factory before key work', async (t) => {
    const expectedMessage = 'cookie.name must be a valid cookie name';
    const invalidNames = ['', 'bad;name', 'bad name', 'bad\tname', 'bad\rname', 'bad\nname', 'bad\u0000name', 'bad=name', 'bad,name', 'bad/name'];
    const cL1 = invalidNames.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const invalidName = invalidNames[iL1];
        await t.throwsAsync(SessionsManager.create({ cookie: { name: invalidName } }), { message: expectedMessage });
    }
    const shortKey = keyFromLength(15);
    await t.throwsAsync(SessionsManager.create({ cookie: { name: '' }, encryptionKey: shortKey }), { message: expectedMessage });
});
test('derived Max-Age follows the validityToken in whole seconds', async (t) => {
    const cases = [
        { maxAge: 1, validityToken: 1 },
        { maxAge: 1, validityToken: 1000 },
        { maxAge: 2, validityToken: 1001 },
        { maxAge: 3600, validityToken: 3_600_000 }
    ];
    const cL1 = cases.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const maxAgeCase = cases[iL1];
        const manager = await SessionsManager.create({ validityToken: maxAgeCase.validityToken, encryptionKey: key16 });
        const app = createTestApp(manager);
        const response = await app.request('/create', { method: 'POST' });
        const headers = response.headers.getSetCookie();
        t.is(headers.length, 1);
        const header = headers[0];
        t.true(header.includes(`Max-Age=${maxAgeCase.maxAge}`));
        t.false(header.includes('Expires='));
    }
});
test('the maximum validityToken is accepted and one millisecond more is rejected', async (t) => {
    const manager = await SessionsManager.create({ validityToken: 34_560_000_000, encryptionKey: key16 });
    const app = createTestApp(manager);
    const response = await app.request('/create', { method: 'POST' });
    const headers = response.headers.getSetCookie();
    t.is(headers.length, 1);
    t.true(headers[0].includes('Max-Age=34560000'));
    await t.throwsAsync(SessionsManager.create({ validityToken: 34_560_000_001 }), { message: 'validityToken must not exceed 34560000000 milliseconds (400 days)' });
});
test('cross-site and partitioned modes reject secure false at the factory', async (t) => {
    const modes = ['cross-site', 'partitioned'];
    const expectedMessage = "cookie.mode 'cross-site' and 'partitioned' require cookie.secure to be true";
    const cL1 = modes.length;
    for (let iL1 = 0; iL1 < cL1; iL1++) {
        const mode = modes[iL1];
        await t.throwsAsync(SessionsManager.create({ cookie: { mode, secure: false } }), { message: expectedMessage });
    }
});
test('a configured domain and path appear on creation, renewal, and deletion without Expires', async (t) => {
    const manager = await SessionsManager.create({ cookie: { domain: 'example.com', path: '/auth' }, encryptionKey: key16 });
    const app = createTestApp(manager);
    const created = await app.request('/create', { method: 'POST' });
    const createdHeaders = created.headers.getSetCookie();
    t.is(createdHeaders.length, 1);
    const createdHeader = createdHeaders[0];
    t.true(createdHeader.includes('Domain=example.com'));
    t.true(createdHeader.includes('Path=/auth'));
    t.true(createdHeader.includes('Max-Age=3600'));
    t.true(createdHeader.includes('Secure'));
    t.false(createdHeader.includes('Expires='));
    const token = tokenFromSetCookie(createdHeader);
    const verified = await verifyResponse(app, token);
    const verifiedHeaders = verified.headers.getSetCookie();
    t.is(verifiedHeaders.length, 1);
    const verifiedHeader = verifiedHeaders[0];
    t.true(verifiedHeader.includes('Domain=example.com'));
    t.true(verifiedHeader.includes('Path=/auth'));
    t.true(verifiedHeader.includes('Max-Age=3600'));
    t.true(verifiedHeader.includes('Secure'));
    t.false(verifiedHeader.includes('Expires='));
    const logout = await app.request('/logout', { method: 'POST', headers: { cookie: cookieHeader(token) } });
    const logoutHeaders = logout.headers.getSetCookie();
    t.is(logoutHeaders.length, 2);
    const deletion = logoutHeaders[1];
    t.true(deletion.includes('Domain=example.com'));
    t.true(deletion.includes('Path=/auth'));
    t.true(deletion.includes('Max-Age=0'));
    t.true(deletion.includes('Secure'));
    t.false(deletion.includes('Expires='));
});
test.serial('subtle overrides restore the exact pre-override property state of crypto.subtle', (t) => {
    const absentDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    const sabotage = sabotageEncrypt();
    const sabotagedDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    sabotage.restore();
    t.truthy(sabotagedDescriptor);
    t.deepEqual(Object.getOwnPropertyDescriptor(crypto, 'subtle'), absentDescriptor);
    const fixtureDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    try {
        Object.defineProperty(crypto, 'subtle', { value: crypto.subtle, configurable: true });
        const installedDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
        const override = overrideSubtle((sabotaged, original) => {
            sabotaged.encrypt = (...args) => original.encrypt(...args);
        });
        try {
            t.truthy(Object.getOwnPropertyDescriptor(crypto, 'subtle'));
        }
        finally {
            override.restore();
        }
        t.deepEqual(Object.getOwnPropertyDescriptor(crypto, 'subtle'), installedDescriptor);
    }
    finally {
        if (fixtureDescriptor) {
            Object.defineProperty(crypto, 'subtle', fixtureDescriptor);
        }
        else {
            delete crypto['subtle'];
        }
    }
    t.deepEqual(Object.getOwnPropertyDescriptor(crypto, 'subtle'), absentDescriptor);
});
test('the options types reject removed and invalid fields at compile time', async (t) => {
    const obsoleteOptions = {
        // @ts-expect-error algo is removed; sessions always use fixed AES-GCM.
        algo: { name: 'AES-GCM', length: 256, tagLength: 128 },
        encryptionKey: key32
    };
    const removedExpires = {
        cookie: {
            // @ts-expect-error expires is removed; the cookie lifetime derives from validityToken.
            expires: new Date()
        }
    };
    const removedHttpOnly = {
        cookie: {
            // @ts-expect-error httpOnly is removed; the cookie is always HttpOnly.
            httpOnly: false
        }
    };
    const removedMaxAge = {
        cookie: {
            // @ts-expect-error maxAge is removed; Max-Age derives from validityToken.
            maxAge: 3600
        }
    };
    const removedPartitioned = {
        cookie: {
            // @ts-expect-error partitioned is removed; use mode 'partitioned'.
            partitioned: true
        }
    };
    const removedPriority = {
        cookie: {
            // @ts-expect-error priority is removed.
            priority: 'High'
        }
    };
    const removedSameSite = {
        cookie: {
            // @ts-expect-error sameSite is removed; use mode.
            sameSite: 'Strict'
        }
    };
    const invalidMode = {
        // @ts-expect-error 'none' is not a valid cookie mode.
        mode: 'none'
    };
    const validMode = 'partitioned';
    const validName = 'custom';
    const manager = await SessionsManager.create(obsoleteOptions);
    t.truthy(manager);
    t.truthy(removedExpires);
    t.truthy(removedHttpOnly);
    t.truthy(removedMaxAge);
    t.truthy(removedPartitioned);
    t.truthy(removedPriority);
    t.truthy(removedSameSite);
    t.truthy(invalidMode);
    t.is(validMode, 'partitioned');
    t.is(validName, 'custom');
});
test('the package exports the SessionsManager class and no longer exports the free factory', (t) => {
    t.false('createSessionsManager' in packageModule);
    t.true('function' === typeof packageModule.SessionsManager);
    t.is(packageModule.SessionsManager.name, 'SessionsManager');
});

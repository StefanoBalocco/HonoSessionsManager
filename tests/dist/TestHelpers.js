import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
export function createTestApp(manager, cookieName = 'session') {
    const app = new Hono();
    app.use('*', manager.middleware);
    app.post('/create', async (context) => {
        await manager.create(context);
        return context.json({ created: true });
    });
    app.get('/verify', (context) => {
        const session = context.get('session');
        return context.json({ authenticated: undefined !== session });
    });
    app.post('/set/:key', async (context) => {
        const session = context.get('session');
        let returnValue;
        if (session) {
            const key = context.req.param('key') ?? '';
            const value = await context.req.json();
            const stored = await session.data.set(key, value);
            returnValue = context.json({ stored });
        }
        else {
            returnValue = context.json({ stored: false }, 401);
        }
        return returnValue;
    });
    app.get('/get/:key', async (context) => {
        const session = context.get('session');
        let returnValue;
        if (session) {
            const key = context.req.param('key') ?? '';
            const value = await session.data.get(key);
            returnValue = context.json({ value: undefined === value ? null : value });
        }
        else {
            returnValue = context.json({ value: null }, 401);
        }
        return returnValue;
    });
    app.post('/logout', async (context) => {
        const token = getCookie(context, cookieName);
        const deleted = await manager.delete(context, token ?? '');
        const cleared = undefined === context.get('session');
        return context.json({ cleared, deleted });
    });
    return app;
}
export function cookiePairFrom(setCookieValue) {
    const returnValue = setCookieValue.split(';')[0];
    return returnValue;
}
export function tokenFromSetCookie(setCookieValue) {
    const pair = cookiePairFrom(setCookieValue);
    const separatorIndex = pair.indexOf('=');
    const returnValue = pair.slice(separatorIndex + 1);
    return returnValue;
}
export function assertNoSetCookie(t, response) {
    t.is(response.headers.get('set-cookie'), null);
}
export function jsonResponse(response) {
    const returnValue = response.json();
    return returnValue;
}
export { Base64UrlDecode as base64UrlDecode, Base64UrlEncode as base64UrlEncode } from '../../dist/Utilities.js';

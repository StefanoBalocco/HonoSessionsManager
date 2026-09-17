import test from 'ava';
import { SessionsStorage } from '../../dist/index.js';
const secretA = secretFromBytes([1, 2, 3]);
const secretB = secretFromBytes([4, 5, 6]);
const secretC = secretFromBytes([7, 8, 9]);
function secretFromBytes(bytes) {
    const returnValue = new Uint8Array(bytes.length);
    for (let iL1 = 0; iL1 < bytes.length; iL1++) {
        returnValue[iL1] = bytes[iL1];
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
test('the root package exposes the SessionsStorage contract type and the Local value together', async (t) => {
    const storage = new SessionsStorage.Local();
    t.true(storage instanceof SessionsStorage.Local);
    const [sessionId, session] = await storage.create(secretA, 1_000);
    t.is(sessionId, 0);
    t.deepEqual(Object.keys(session).sort(), ['data']);
});
test('create returns the first free id and a data-only session', async (t) => {
    const storage = new SessionsStorage.Local();
    const [sessionId, session] = await storage.create(secretA, 1_000);
    t.is(sessionId, 0);
    t.deepEqual(Object.keys(session).sort(), ['data']);
});
test('session exposes no runtime sessionId or secret', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    t.false('sessionId' in session);
    t.false('secret' in session);
});
test('get resolves undefined for a missing key', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    const missing = await session.data.get('missing');
    t.is(missing, undefined);
});
test('set returns true and get returns the stored value', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    t.true(await session.data.set('answer', 42));
    const stored = await session.data.get('answer');
    t.is(stored, 42);
});
test('delete returns true only for an existing key', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    t.false(await session.data.delete('absent'));
    t.true(await session.data.set('key', 'value'));
    t.true(await session.data.delete('key'));
    t.false(await session.data.delete('key'));
    const removed = await session.data.get('key');
    t.is(removed, undefined);
});
test('setting getting and deleting the proto key stores an own data property', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    t.true(await session.data.set('__proto__', { polluted: true }));
    const stored = await session.data.get('__proto__');
    t.deepEqual(stored, { polluted: true });
    t.true(await session.data.delete('__proto__'));
    t.is(await session.data.get('__proto__'), undefined);
    const freshObject = {};
    t.is(Object.getPrototypeOf(freshObject), Object.prototype);
    t.false('polluted' in freshObject);
});
test('stored nested values do not change when the caller mutates the original after set', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    const original = { nested: [1, 2] };
    t.true(await session.data.set('payload', original));
    original.nested.push(3);
    const stored = await session.data.get('payload');
    t.deepEqual(stored, { nested: [1, 2] });
});
test('returned values do not mutate stored values when the caller mutates them after get', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    await session.data.set('payload', { nested: [1, 2] });
    const retrieved = await session.data.get('payload');
    if (retrieved && 'object' === typeof retrieved && !Array.isArray(retrieved)) {
        const record = retrieved;
        const nested = record['nested'];
        if (Array.isArray(nested)) {
            nested.push(3);
        }
    }
    const storedAgain = await session.data.get('payload');
    t.deepEqual(storedAgain, { nested: [1, 2] });
});
test('set accepts a valid nested JSON value', async (t) => {
    const storage = new SessionsStorage.Local();
    const session = (await storage.create(secretA, 1_000))[1];
    const nested = { user: { name: 'ada', active: true, score: 9.5, note: null, tags: ['a', 'b'] } };
    t.true(await session.data.set('profile', nested));
    t.deepEqual(await session.data.get('profile'), nested);
});
test('ids allocate sequentially as first free', async (t) => {
    const storage = new SessionsStorage.Local();
    const first = (await storage.create(secretA, 1_000_000))[0];
    const second = (await storage.create(secretB, 1_000_000))[0];
    const third = (await storage.create(secretC, 1_000_000))[0];
    t.is(first, 0);
    t.is(second, 1);
    t.is(third, 2);
    t.true(await storage.delete(1, secretB));
    const reused = (await storage.create(secretB, 1_000_000))[0];
    const next = (await storage.create(secretB, 1_000_000))[0];
    t.is(reused, 1);
    t.is(next, 3);
});
test('deleted ids are immediately reusable and the old credential stops working', async (t) => {
    const storage = new SessionsStorage.Local();
    const [sessionId] = await storage.create(secretA, 1_000_000);
    t.true(await storage.delete(sessionId, secretA));
    t.is(await storage.verify(sessionId, secretA, 1_000_000), undefined);
    const [reusedId, reusedSession] = await storage.create(secretB, 1_000_000);
    t.is(reusedId, sessionId);
    t.is(await reusedSession.data.get('marker'), undefined);
    await reusedSession.data.set('marker', 'B');
    const stored = await reusedSession.data.get('marker');
    t.is(stored, 'B');
});
test('expired sessions at equality are removed and their id reused', async (t) => {
    const clock = fakeClockAt(1_000);
    try {
        const storage = new SessionsStorage.Local();
        const [sessionId] = await storage.create(secretA, 100);
        clock.advance(100);
        t.is(await storage.verify(sessionId, secretA, 100), undefined);
        const [reusedId] = await storage.create(secretB, 100);
        t.is(reusedId, sessionId);
        const replacement = await storage.verify(reusedId, secretB, 100);
        if (replacement) {
            t.true(await replacement.data.set('marker', 'B'));
        }
        if (!replacement) {
            t.fail('Replacement session must verify');
        }
    }
    finally {
        clock.restore();
    }
});
test('wrong secret cannot verify or delete', async (t) => {
    const storage = new SessionsStorage.Local();
    const [sessionId] = await storage.create(secretA, 1_000_000);
    t.is(await storage.verify(sessionId, secretB, 1_000_000), undefined);
    t.false(await storage.delete(sessionId, secretB));
    const intact = await storage.verify(sessionId, secretA, 1_000_000);
    if (intact) {
        t.true(await intact.data.set('marker', 'kept'));
    }
    t.true(await storage.delete(sessionId, secretA));
    t.is(await storage.verify(sessionId, secretA, 1_000_000), undefined);
});
test('verification slides expiry forward', async (t) => {
    const clock = fakeClockAt(1_000);
    try {
        const storage = new SessionsStorage.Local();
        const [sessionId] = await storage.create(secretA, 100);
        clock.advance(50);
        const slid = await storage.verify(sessionId, secretA, 100);
        if (slid) {
            t.true(await slid.data.set('marker', 'slid'));
        }
        if (!slid) {
            t.fail('Session must verify before the deadline');
        }
        clock.advance(99);
        const stillValid = await storage.verify(sessionId, secretA, 100);
        if (stillValid) {
            t.pass('Sliding window kept the session alive past the original deadline');
        }
        if (!stillValid) {
            t.fail('Session must stay valid inside the slid window');
        }
        clock.advance(100);
        t.is(await storage.verify(sessionId, secretA, 100), undefined);
        const [reusedId] = await storage.create(secretB, 100);
        t.is(reusedId, sessionId);
    }
    finally {
        clock.restore();
    }
});
test('old session facades stay detached after delete and same-id reuse', async (t) => {
    const storage = new SessionsStorage.Local();
    const [sessionId, oldSession] = await storage.create(secretA, 1_000_000);
    await oldSession.data.set('who', 'A');
    t.true(await storage.delete(sessionId, secretA));
    const [reusedId, newSession] = await storage.create(secretB, 1_000_000);
    t.is(reusedId, sessionId);
    t.is(await newSession.data.get('who'), undefined);
    await newSession.data.set('who', 'B');
    await oldSession.data.set('who', 'A2');
    const newStored = await newSession.data.get('who');
    const oldStored = await oldSession.data.get('who');
    t.is(newStored, 'B');
    t.is(oldStored, 'A2');
    const verified = await storage.verify(reusedId, secretB, 1_000_000);
    if (verified) {
        t.is(await verified.data.get('who'), 'B');
    }
    if (!verified) {
        t.fail('Replacement session must verify');
    }
});
test('synchronous methods return plain values satisfying Promisable', async (t) => {
    const storage = new SessionsStorage.Local();
    const created = storage.create(secretA, 1_000);
    t.false(created instanceof Promise);
    const [, session] = await created;
    const setResult = session.data.set('key', 1);
    t.false(setResult instanceof Promise);
    t.true(await setResult);
    const getResult = session.data.get('key');
    t.false(getResult instanceof Promise);
    t.is(await getResult, 1);
    const deleteResult = session.data.delete('key');
    t.false(deleteResult instanceof Promise);
    t.true(await deleteResult);
    const verifyResult = storage.verify(0, secretA, 1_000);
    t.false(verifyResult instanceof Promise);
    const deleted = storage.delete(0, secretA);
    t.false(deleted instanceof Promise);
    t.true(await deleted);
});
test('create throws Session array full when the fixed capacity is exhausted', async (t) => {
    const localStatics = SessionsStorage.Local;
    const savedMax = localStatics._sessionsMax;
    const savedThreshold = localStatics._sweepThreshold;
    t.is(savedMax, 0x10000);
    t.is(savedThreshold, 75 / 100 * 0x10000);
    localStatics._sessionsMax = 4;
    localStatics._sweepThreshold = 3;
    try {
        const storage = new SessionsStorage.Local();
        await storage.create(secretA, 1_000_000);
        await storage.create(secretB, 1_000_000);
        await storage.create(secretC, 1_000_000);
        await storage.create(secretA, 1_000_000);
        let threwSessionFull = false;
        try {
            await storage.create(secretB, 1_000_000);
        }
        catch (error) {
            threwSessionFull = (error instanceof Error) && ('Session array full' === error.message);
        }
        t.true(threwSessionFull);
    }
    finally {
        localStatics._sessionsMax = savedMax;
        localStatics._sweepThreshold = savedThreshold;
    }
});
test('create sweeps expired sessions at the sweep threshold and reuses the freed id', async (t) => {
    const clock = fakeClockAt(1_000);
    const localStatics = SessionsStorage.Local;
    const savedMax = localStatics._sessionsMax;
    const savedThreshold = localStatics._sweepThreshold;
    t.is(savedMax, 0x10000);
    t.is(savedThreshold, 75 / 100 * 0x10000);
    localStatics._sessionsMax = 4;
    localStatics._sweepThreshold = 3;
    try {
        const storage = new SessionsStorage.Local();
        const [firstId] = await storage.create(secretA, 100);
        t.is(firstId, 0);
        clock.advance(100);
        const secondId = (await storage.create(secretB, 100))[0];
        const thirdId = (await storage.create(secretC, 100))[0];
        t.is(secondId, 1);
        t.is(thirdId, 2);
        const reusedId = (await storage.create(secretA, 100))[0];
        t.is(reusedId, 0);
        const surviving = await storage.verify(1, secretB, 100);
        if (surviving) {
            t.pass('The first unexpired record survived the sweep');
        }
        if (!surviving) {
            t.fail('The first unexpired record must survive the sweep and verify');
        }
    }
    finally {
        clock.restore();
        localStatics._sessionsMax = savedMax;
        localStatics._sweepThreshold = savedThreshold;
    }
});

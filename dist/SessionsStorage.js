import * as Utilities from './Utilities.js';
export var SessionsStorage;
(function (SessionsStorage) {
    class Local {
        static _sessionsMax = 0x10000;
        static _sweepThreshold = 75 / 100 * Local._sessionsMax;
        _sessions = new Map();
        create(secret, validityToken) {
            const now = Date.now();
            if (Local._sweepThreshold <= this._sessions.size) {
                for (const [entryId, entryStored] of this._sessions) {
                    if ((entryStored.lastUsed + validityToken) <= now) {
                        this._sessions.delete(entryId);
                    }
                }
            }
            let id = 0;
            while ((Local._sessionsMax > id) && this._sessions.has(id)) {
                id++;
            }
            id = ((Local._sessionsMax === id) ? -1 : id);
            if (-1 < id) {
                const data = {};
                const sessionStored = {
                    sessionId: id,
                    secret: secret.slice(),
                    lastUsed: now,
                    data: {
                        get: (key) => {
                            let returnValue;
                            if (Object.hasOwn(data, key)) {
                                returnValue = structuredClone(data[key]);
                            }
                            else {
                                returnValue = undefined;
                            }
                            return returnValue;
                        },
                        set: (key, value) => {
                            Object.defineProperty(data, key, {
                                value: structuredClone(value),
                                writable: true,
                                enumerable: true,
                                configurable: true
                            });
                            return true;
                        },
                        delete: (key) => {
                            let returnValue = false;
                            if (Object.hasOwn(data, key)) {
                                delete data[key];
                                returnValue = true;
                            }
                            return returnValue;
                        }
                    }
                };
                this._sessions.set(id, sessionStored);
                return [id, { data: sessionStored.data }];
            }
            else {
                throw new Error('Session array full');
            }
        }
        verify(sessionId, secret, validityToken) {
            const now = Date.now();
            const sessionStored = this._sessions.get(sessionId);
            let returnValue;
            if (sessionStored) {
                if ((sessionStored.lastUsed + validityToken) <= now) {
                    this._sessions.delete(sessionId);
                }
                else if (Utilities.TimingSafeEqual(sessionStored.secret, secret)) {
                    sessionStored.lastUsed = now;
                    returnValue = { data: sessionStored.data };
                }
            }
            return returnValue;
        }
        delete(sessionId, secret) {
            const sessionStored = this._sessions.get(sessionId);
            let returnValue = false;
            if (sessionStored && Utilities.TimingSafeEqual(sessionStored.secret, secret)) {
                returnValue = this._sessions.delete(sessionId);
            }
            return returnValue;
        }
    }
    SessionsStorage.Local = Local;
})(SessionsStorage || (SessionsStorage = {}));

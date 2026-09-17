import type { Promisable, Session, Undefinedable } from './types.js';
export interface SessionsStorage {
    create(secret: Uint8Array<ArrayBuffer>, validityToken: number): Promisable<[number, Session]>;
    verify(sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number): Promisable<Undefinedable<Session>>;
    delete(sessionId: number, secret: Uint8Array<ArrayBuffer>): Promisable<boolean>;
}
export declare namespace SessionsStorage {
    class Local implements SessionsStorage {
        private static readonly _sessionsMax;
        private static readonly _sweepThreshold;
        private readonly _sessions;
        create(secret: Uint8Array<ArrayBuffer>, validityToken: number): Promisable<[number, Session]>;
        verify(sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number): Promisable<Undefinedable<Session>>;
        delete(sessionId: number, secret: Uint8Array<ArrayBuffer>): Promisable<boolean>;
    }
}

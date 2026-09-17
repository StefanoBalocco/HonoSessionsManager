import type { Context, MiddlewareHandler } from 'hono';
import { SessionsStorage } from './SessionsStorage.js';
import type { Session, Undefinedable } from './types.js';
export type SessionsEnv = {
    Variables: {
        session: Undefinedable<Session>;
    };
};
export type SessionsManagerOptions = {
    readonly cookie?: {
        readonly domain?: string;
        readonly mode?: ('strict' | 'lax' | 'cross-site' | 'partitioned');
        readonly name?: string;
        readonly path?: string;
        readonly secure?: boolean;
    };
    readonly encryptionKey?: Uint8Array<ArrayBuffer>;
    readonly storage?: SessionsStorage;
    readonly validityToken?: number;
};
export declare class SessionsManager {
    private static readonly _cookieNamePattern;
    private static readonly _secretLength;
    private static readonly _ivLength;
    private static readonly _tagLength;
    private static readonly _defaultValidityToken;
    private static readonly _maxValidityToken;
    private static readonly _textEncoder;
    private static readonly _utf8Decoder;
    private readonly _cryptoKey;
    private readonly _cookieName;
    private readonly _cookieOptions;
    private readonly _storage;
    private readonly _validityToken;
    readonly middleware: MiddlewareHandler<SessionsEnv>;
    private constructor();
    static create(options?: SessionsManagerOptions): Promise<SessionsManager>;
    create(context: Context<SessionsEnv>): Promise<Session>;
    verify(context: Context<SessionsEnv>, token: string): Promise<Undefinedable<Session>>;
    delete(context: Context<SessionsEnv>, token: string): Promise<boolean>;
    private _decodeCredential;
}

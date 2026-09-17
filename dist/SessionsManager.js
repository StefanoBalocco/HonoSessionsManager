import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { SessionsStorage } from './SessionsStorage.js';
import * as Utilities from './Utilities.js';
export class SessionsManager {
    static _cookieNamePattern = /^[\w!#$%&'*.^`|~+-]+$/;
    static _secretLength = 32;
    static _ivLength = 12;
    static _tagLength = 64;
    static _defaultValidityToken = 3_600_000;
    static _maxValidityToken = 34_560_000_000;
    static _textEncoder = new TextEncoder();
    static _utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    _cryptoKey;
    _cookieName;
    _cookieOptions;
    _storage;
    _validityToken;
    middleware;
    constructor(cryptoKey, cookieName, cookieOptions, storage, validityToken) {
        this._cryptoKey = cryptoKey;
        this._cookieName = cookieName;
        this._cookieOptions = cookieOptions;
        this._storage = storage;
        this._validityToken = validityToken;
        this.middleware = async (context, next) => {
            context.set('session', undefined);
            const token = getCookie(context, this._cookieName);
            if (token) {
                await this.verify(context, token);
            }
            await next();
        };
    }
    static async create(options) {
        const validityToken = options?.validityToken ?? SessionsManager._defaultValidityToken;
        if (Number.isSafeInteger(validityToken)) {
            if (1 <= validityToken) {
                if (SessionsManager._maxValidityToken >= validityToken) {
                    const cookieName = options?.cookie?.name ?? 'session';
                    if (SessionsManager._cookieNamePattern.test(cookieName)) {
                        const path = options?.cookie?.path ?? '/';
                        if (path.startsWith('/')) {
                            const cookieOptions = {
                                domain: options?.cookie?.domain,
                                httpOnly: true,
                                maxAge: Math.ceil(validityToken / 1000),
                                partitioned: false,
                                path: path,
                                sameSite: 'Lax',
                                secure: options?.cookie?.secure ?? true
                            };
                            const mode = options?.cookie?.mode ?? 'lax';
                            if (cookieOptions.secure || ['strict', 'lax'].includes(mode)) {
                                switch (mode) {
                                    case 'strict': {
                                        cookieOptions.sameSite = 'Strict';
                                        break;
                                    }
                                    case 'lax': {
                                        break;
                                    }
                                    default: {
                                        cookieOptions.sameSite = 'None';
                                        if ('partitioned' === mode) {
                                            cookieOptions.partitioned = true;
                                        }
                                    }
                                }
                                const storage = options?.storage ?? new SessionsStorage.Local();
                                let cryptoKey;
                                if (options?.encryptionKey) {
                                    cryptoKey = await crypto.subtle.importKey('raw', options.encryptionKey.slice(), 'AES-GCM', false, ['encrypt', 'decrypt']);
                                }
                                else {
                                    cryptoKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt', 'decrypt']);
                                }
                                return new SessionsManager(cryptoKey, cookieName, cookieOptions, storage, validityToken);
                            }
                            else {
                                throw new Error("cookie.mode 'cross-site' and 'partitioned' require cookie.secure to be true");
                            }
                        }
                        else {
                            throw new Error('cookie.path must be a non-empty absolute path starting with /');
                        }
                    }
                    else {
                        throw new Error('cookie.name must be a valid cookie name');
                    }
                }
                else {
                    throw new Error('validityToken must not exceed 34560000000 milliseconds (400 days)');
                }
            }
            else {
                throw new Error('validityToken must be a positive safe integer');
            }
        }
        else {
            throw new Error('validityToken must be a positive safe integer');
        }
    }
    async create(context) {
        const secret = new Uint8Array(SessionsManager._secretLength);
        crypto.getRandomValues(secret);
        const [sessionId, session] = await this._storage.create(secret, this._validityToken);
        try {
            const iv = new Uint8Array(SessionsManager._ivLength);
            crypto.getRandomValues(iv);
            const plaintext = JSON.stringify([sessionId, Utilities.Base64UrlEncode(secret)]);
            const encrypted = await crypto.subtle.encrypt({ name: this._cryptoKey.algorithm.name, iv, tagLength: SessionsManager._tagLength }, this._cryptoKey, SessionsManager._textEncoder.encode(plaintext));
            const combined = new Uint8Array(SessionsManager._ivLength + encrypted.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encrypted), SessionsManager._ivLength);
            const token = Utilities.Base64UrlEncode(combined);
            setCookie(context, this._cookieName, token, this._cookieOptions);
            context.set('session', session);
        }
        catch (error) {
            try {
                await this._storage.delete(sessionId, secret);
            }
            catch {
            }
            throw error;
        }
        return session;
    }
    async verify(context, token) {
        context.set('session', undefined);
        const credential = await this._decodeCredential(token);
        let returnValue;
        if (credential) {
            const [sessionId, secret] = credential;
            returnValue = await this._storage.verify(sessionId, secret, this._validityToken);
            if (returnValue) {
                setCookie(context, this._cookieName, token, this._cookieOptions);
                context.set('session', returnValue);
            }
        }
        return returnValue;
    }
    async delete(context, token) {
        let returnValue = false;
        const credential = await this._decodeCredential(token);
        if (credential) {
            const [sessionId, secret] = credential;
            returnValue = await this._storage.delete(sessionId, secret);
        }
        deleteCookie(context, this._cookieName, this._cookieOptions);
        context.set('session', undefined);
        return returnValue;
    }
    async _decodeCredential(token) {
        let returnValue;
        try {
            const bytes = Utilities.Base64UrlDecode(token);
            if (SessionsManager._ivLength < bytes.length) {
                const iv = bytes.slice(0, SessionsManager._ivLength);
                const ciphertext = bytes.slice(SessionsManager._ivLength);
                const plaintext = await crypto.subtle.decrypt({ name: this._cryptoKey.algorithm.name, iv, tagLength: SessionsManager._tagLength }, this._cryptoKey, ciphertext);
                const plaintextText = SessionsManager._utf8Decoder.decode(plaintext);
                const tuple = JSON.parse(plaintextText);
                if (Array.isArray(tuple) && (2 === tuple.length)) {
                    const sessionId = tuple[0];
                    const secretText = tuple[1];
                    if (('number' === typeof sessionId) && Number.isSafeInteger(sessionId) && (0 <= sessionId) && ('string' === typeof secretText)) {
                        const secret = Utilities.Base64UrlDecode(secretText);
                        if ((SessionsManager._secretLength === secret.length) && (JSON.stringify([sessionId, secretText]) === plaintextText)) {
                            returnValue = [sessionId, secret];
                        }
                    }
                }
            }
        }
        catch {
        }
        return returnValue;
    }
}

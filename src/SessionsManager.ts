import type { Context, MiddlewareHandler, Next } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { SessionsStorage } from './SessionsStorage.js';
import type { Session, Undefinedable } from './types.js';
import * as Utilities from './Utilities.js';
import type { CookieOptions } from 'hono/utils/cookie';

export type SessionsEnv = {
  Variables: {
    session: Undefinedable<Session>
  }
}

export type SessionsManagerOptions = {
  readonly cookie?: {
    readonly domain?: string,
    readonly mode?: ( 'strict' | 'lax' | 'cross-site' | 'partitioned' ),
    readonly name?: string,
    readonly path?: string,
    readonly secure?: boolean
  },
  readonly encryptionKey?: Uint8Array<ArrayBuffer>,
  readonly storage?: SessionsStorage,
  readonly validityToken?: number
}

export class SessionsManager {
  private static readonly _cookieNamePattern: RegExp = /^[\w!#$%&'*.^`|~+-]+$/;
  private static readonly _secretLength: number = 32;
  private static readonly _ivLength: number = 12;
  private static readonly _tagLength: number = 64;
  private static readonly _defaultValidityToken: number = 3_600_000;
  private static readonly _maxValidityToken: number = 34_560_000_000;
  private static readonly _textEncoder: TextEncoder = new TextEncoder();
  // ignoreBOM keeps a leading U+FEFF in the decoded text so BOM-wrapped plaintext fails the canonical equality check.
  private static readonly _utf8Decoder: TextDecoder = new TextDecoder( 'utf-8', { fatal: true, ignoreBOM: true } );

  private readonly _cryptoKey: CryptoKey;
  private readonly _cookieName: string;
  private readonly _cookieOptions: CookieOptions;
  private readonly _storage: SessionsStorage;
  private readonly _validityToken: number;

  public readonly middleware: MiddlewareHandler<SessionsEnv>;

  private constructor( cryptoKey: CryptoKey, cookieName: string, cookieOptions: CookieOptions, storage: SessionsStorage, validityToken: number ) {
    this._cryptoKey = cryptoKey;
    this._cookieName = cookieName;
    this._cookieOptions = cookieOptions;
    this._storage = storage;
    this._validityToken = validityToken;
    this.middleware = async( context: Context<SessionsEnv>, next: Next ): Promise<void> => {
      context.set( 'session', undefined );
      const token: Undefinedable<string> = getCookie( context, this._cookieName );
      if( token ) {
        await this.verify( context, token );
      }
      await next();
    };
  }

  public static async create( options?: SessionsManagerOptions ): Promise<SessionsManager> {
    const validityToken: number = options?.validityToken ?? SessionsManager._defaultValidityToken;
    if( Number.isSafeInteger( validityToken ) ) {
      if( 1 <= validityToken ) {
        if( SessionsManager._maxValidityToken >= validityToken ) {
          const cookieName: string = options?.cookie?.name ?? 'session';
          if( SessionsManager._cookieNamePattern.test( cookieName ) ) {
            const path : string = options?.cookie?.path ?? '/';
            if( path.startsWith( '/' ) ) {
              const cookieOptions: CookieOptions = {
                  domain: options?.cookie?.domain,
                  httpOnly: true,
                  maxAge: Math.ceil( validityToken / 1000 ),
                  partitioned: false,
                  path: path,
                  sameSite: 'Lax',
                  secure: options?.cookie?.secure ?? true
              };
              const mode : NonNullable<SessionsManagerOptions['cookie']>['mode'] = options?.cookie?.mode ?? 'lax';
              if( cookieOptions.secure || [ 'strict', 'lax' ].includes( mode ) ) {
                switch( mode ) {
                  case 'strict': {
                    cookieOptions.sameSite = 'Strict';
                    break;
                  }
                  case 'lax': {
                    break;
                  }
                  default: {
                    cookieOptions.sameSite = 'None';
                    if( 'partitioned' === mode ) {
                      cookieOptions.partitioned = true;
                    }
                  }
                }
                const storage: SessionsStorage = options?.storage ?? new SessionsStorage.Local();
                let cryptoKey: CryptoKey;

                if( options?.encryptionKey ) {
                  cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    options.encryptionKey.slice(),
                    'AES-GCM',
                    false,
                    [ 'encrypt', 'decrypt' ]
                  );
                } else {
                  cryptoKey = await crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 128 },
                    false,
                    [ 'encrypt', 'decrypt' ]
                  );
                }
                return new SessionsManager( cryptoKey, cookieName, cookieOptions, storage, validityToken );
              } else {
                throw new Error( "cookie.mode 'cross-site' and 'partitioned' require cookie.secure to be true" );
              }
            } else {
              throw new Error( 'cookie.path must be a non-empty absolute path starting with /' );
            }
          } else {
            throw new Error( 'cookie.name must be a valid cookie name' );
          }
        } else {
          throw new Error( 'validityToken must not exceed 34560000000 milliseconds (400 days)' );
        }
      } else {
        throw new Error( 'validityToken must be a positive safe integer' );
      }
    } else {
      throw new Error( 'validityToken must be a positive safe integer' );
    }
  }

  public async create( context: Context<SessionsEnv> ): Promise<Session> {
    const secret: Uint8Array<ArrayBuffer> = new Uint8Array( SessionsManager._secretLength );
    crypto.getRandomValues( secret );
    const [ sessionId, session ]: [ number, Session ] = await this._storage.create( secret, this._validityToken );
    try {
      const iv: Uint8Array<ArrayBuffer> = new Uint8Array( SessionsManager._ivLength );
      crypto.getRandomValues( iv );
      const plaintext: string = JSON.stringify( [ sessionId, Utilities.Base64UrlEncode( secret ) ] );
      const encrypted: ArrayBuffer = await crypto.subtle.encrypt(
        { name: this._cryptoKey.algorithm.name, iv, tagLength: SessionsManager._tagLength },
        this._cryptoKey,
        SessionsManager._textEncoder.encode( plaintext )
      );
      const combined: Uint8Array<ArrayBuffer> = new Uint8Array( SessionsManager._ivLength + encrypted.byteLength );
      combined.set( iv, 0 );
      combined.set( new Uint8Array<ArrayBuffer>( encrypted ), SessionsManager._ivLength );
      const token: string = Utilities.Base64UrlEncode( combined );
      setCookie( context, this._cookieName, token, this._cookieOptions );
      context.set( 'session', session );
    } catch( error: unknown ) {
      try {
        await this._storage.delete( sessionId, secret );
      } catch {
        // Cleanup is best effort; the original issuance error is rethrown below.
      }
      throw error;
    }
    return session;
  }

  public async verify( context: Context<SessionsEnv>, token: string ): Promise<Undefinedable<Session>> {
    context.set( 'session', undefined );
    const credential: Undefinedable<[ number, Uint8Array<ArrayBuffer> ]> = await this._decodeCredential( token );
    let returnValue: Undefinedable<Session>;
    if( credential ) {
      const [ sessionId, secret ]: [ number, Uint8Array<ArrayBuffer> ] = credential;
      returnValue = await this._storage.verify( sessionId, secret, this._validityToken );
      if( returnValue ) {
        setCookie( context, this._cookieName, token, this._cookieOptions );
        context.set( 'session', returnValue );
      }
    }
    return returnValue;
  }

  public async delete( context: Context<SessionsEnv>, token: string ): Promise<boolean> {
    let returnValue: boolean = false;
    const credential: Undefinedable<[ number, Uint8Array<ArrayBuffer> ]> = await this._decodeCredential( token );
    if( credential ) {
      const [ sessionId, secret ]: [ number, Uint8Array<ArrayBuffer> ] = credential;
      returnValue = await this._storage.delete( sessionId, secret );
    }
    deleteCookie( context, this._cookieName, this._cookieOptions );
    context.set( 'session', undefined );
    return returnValue;
  }

  private async _decodeCredential( token: string ): Promise<Undefinedable<[ number, Uint8Array<ArrayBuffer> ]>> {
    let returnValue: Undefinedable<[ number, Uint8Array<ArrayBuffer> ]>;
    try {
      const bytes: Uint8Array<ArrayBuffer> = Utilities.Base64UrlDecode( token );
      if( SessionsManager._ivLength < bytes.length ) {
        const iv: Uint8Array<ArrayBuffer> = bytes.slice( 0, SessionsManager._ivLength );
        const ciphertext: Uint8Array<ArrayBuffer> = bytes.slice( SessionsManager._ivLength );
        const plaintext: ArrayBuffer = await crypto.subtle.decrypt(
          { name: this._cryptoKey.algorithm.name, iv, tagLength: SessionsManager._tagLength },
          this._cryptoKey,
          ciphertext
        );
        const plaintextText: string = SessionsManager._utf8Decoder.decode( plaintext );
        const tuple: unknown = JSON.parse( plaintextText );
        if( Array.isArray( tuple ) && ( 2 === tuple.length ) ) {
          const sessionId: unknown = tuple[ 0 ];
          const secretText: unknown = tuple[ 1 ];
          if( ( 'number' === typeof sessionId ) && Number.isSafeInteger( sessionId ) && ( 0 <= sessionId ) && ( 'string' === typeof secretText ) ) {
            const secret: Uint8Array<ArrayBuffer> = Utilities.Base64UrlDecode( secretText );
            if( ( SessionsManager._secretLength === secret.length ) && ( JSON.stringify( [ sessionId, secretText ] ) === plaintextText ) ) {
              returnValue = [ sessionId, secret ];
            }
          }
        }
      }
    } catch {
      // Malformed, tampered, or undecryptable tokens resolve to undefined.
    }
    return returnValue;
  }
}
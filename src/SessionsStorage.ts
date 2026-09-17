import type { JSONValue, Promisable, Session, Undefinedable } from './types.js';
import * as Utilities from './Utilities.js';

/**
 * Pluggable server-side session storage.
 *
 * A `create` implementation returns the session ID it allocated. The ID must be
 * a non-negative safe integer in the inclusive range from `0` to
 * `Number.MAX_SAFE_INTEGER`. The manager trusts this storage contract. The
 * built-in `SessionsStorage.Local` class allocates non-negative IDs through its
 * own allocator.
 */
export interface SessionsStorage {
  create(
    secret: Uint8Array<ArrayBuffer>,
    validityToken: number
  ): Promisable<[ number, Session ]>;

  verify(
    sessionId: number,
    secret: Uint8Array<ArrayBuffer>,
    validityToken: number
  ): Promisable<Undefinedable<Session>>;

  delete(
    sessionId: number,
    secret: Uint8Array<ArrayBuffer>
  ): Promisable<boolean>;
}

export namespace SessionsStorage {
  type SessionStored = {
    readonly sessionId: number,
    readonly secret: Uint8Array<ArrayBuffer>,
    lastUsed: number,
    data: {
      get( key: string ): Promisable<Undefinedable<JSONValue>>,
      set( key: string, value: JSONValue ): Promisable<boolean>,
      delete( key: string ): Promisable<boolean>
    }
  }

  export class Local implements SessionsStorage {
    private static readonly _sessionsMax: number = 0x10000;
    private static readonly _sweepThreshold: number = 75 / 100 * Local._sessionsMax;

    private readonly _sessions: Map<number, SessionStored> = new Map<number, SessionStored>();

    public create( secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<[ number, Session ]> {
      const now: number = Date.now();
      if( Local._sweepThreshold <= this._sessions.size ) {
        for( const [ entryId, entryStored ] of this._sessions ) {
          if( ( entryStored.lastUsed + validityToken ) <= now ) {
            this._sessions.delete( entryId );
          }
        }
      }

      let id: number = 0;
      while( ( Local._sessionsMax > id ) && this._sessions.has( id ) ) {
        id++;
      }
      id = ( ( Local._sessionsMax === id ) ? -1 : id );

      if( -1 < id ) {
        const data: { [ key: string ]: JSONValue } = {};
        const sessionStored: SessionStored = {
          sessionId: id,
          secret: secret.slice(),
          lastUsed: now,
          data: {
            get: ( key: string ): Promisable<Undefinedable<JSONValue>> => {
              let returnValue: Undefinedable<JSONValue>;
              if( Object.hasOwn( data, key ) ) {
                returnValue = structuredClone( data[ key ] );
              } else {
                returnValue = undefined;
              }
              return returnValue;
            },
            set: ( key: string, value: JSONValue ): Promisable<boolean> => {
              Object.defineProperty(
                data,
                key,
                {
                  value: structuredClone( value ),
                  writable: true,
                  enumerable: true,
                  configurable: true
                }
              );
              return true;
            },
            delete: ( key: string ): Promisable<boolean> => {
              let returnValue: boolean = false;
              if( Object.hasOwn( data, key ) ) {
                delete data[ key ];
                returnValue = true;
              }
              return returnValue;
            }
          }
        };
        this._sessions.set( id, sessionStored );
        return [ id, { data: sessionStored.data } ];
      } else {
        throw new Error( 'Session array full' );
      }
    }

    public verify( sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<Undefinedable<Session>> {
      const now: number = Date.now();
      const sessionStored: Undefinedable<SessionStored> = this._sessions.get( sessionId );
      let returnValue: Undefinedable<Session>;
      if( sessionStored ) {
        if( ( sessionStored.lastUsed + validityToken ) <= now ) {
          this._sessions.delete( sessionId );
        } else if( Utilities.TimingSafeEqual( sessionStored.secret, secret ) ) {
          sessionStored.lastUsed = now;
          returnValue = { data: sessionStored.data };
        }
      }
      return returnValue;
    }

    public delete( sessionId: number, secret: Uint8Array<ArrayBuffer> ): Promisable<boolean> {
      const sessionStored: Undefinedable<SessionStored> = this._sessions.get( sessionId );
      let returnValue: boolean = false;
      if( sessionStored && Utilities.TimingSafeEqual( sessionStored.secret, secret ) ) {
        returnValue = this._sessions.delete( sessionId );
      }
      return returnValue;
    }
  }
}
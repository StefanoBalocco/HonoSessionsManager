import test from 'ava';
import { Hono } from 'hono';
import { SessionsManager, SessionsStorage } from '../../dist/index.js';
import * as packageModule from '../../dist/index.js';
import { assertNoSetCookie, base64UrlDecode, base64UrlEncode, cookiePairFrom, createTestApp, jsonResponse, tokenFromSetCookie } from './TestHelpers.js';
import type { Context } from 'hono';
import type { webcrypto } from 'node:crypto';
import type { ExecutionContext } from 'ava';
import type { JSONValue, Promisable, Session, SessionsEnv, SessionsManagerOptions, Undefinedable } from '../../dist/index.js';

type CryptoKey = webcrypto.CryptoKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;
type AlgorithmIdentifier = webcrypto.AlgorithmIdentifier;
type AesGcmParams = webcrypto.AesGcmParams;
type KeyUsage = webcrypto.KeyUsage;
type Subtle = typeof crypto.subtle;

// Non-overloaded signatures so tests can replace individual native methods without fighting overload assignability.
type SubtleCarrier = {
  encrypt( ...args: Parameters<Subtle[ 'encrypt' ]> ): Promise<ArrayBuffer>;
  decrypt( ...args: Parameters<Subtle[ 'decrypt' ]> ): Promise<ArrayBuffer>;
  importKey( ...args: Parameters<Subtle[ 'importKey' ]> ): Promise<CryptoKey>;
  generateKey( algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[] ): Promise<CryptoKey | CryptoKeyPair>;
};

const ivLength: number = 12;
const key16: Uint8Array<ArrayBuffer> = keyFromLength( 16 );
const key24: Uint8Array<ArrayBuffer> = keyFromLength( 24 );
const key32: Uint8Array<ArrayBuffer> = keyFromLength( 32 );
const secretTextOther: string = base64UrlEncode( new Uint8Array( 32 ).fill( 7 ) );
const base64UrlAlphabet: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

type FakeClock = {
  advance( milliseconds: number ): void;
  restore(): void;
};

type Credential = {
  readonly secretText: string;
  readonly sessionId: number;
};

type SubtleOverride = {
  restore(): void;
};

type GenerateKeyCall = {
  readonly algorithm: AlgorithmIdentifier;
  readonly extractable: boolean;
  readonly keyUsages: KeyUsage[];
};

type CookieModeCase = {
  readonly mode: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'mode' ]>;
  readonly partitioned: boolean;
  readonly sameSite: string;
};

type MaxAgeCase = {
  readonly maxAge: number;
  readonly validityToken: number;
};

class AsyncSessionsStorage implements SessionsStorage {
  private readonly _inner: SessionsStorage.Local;

  public constructor() {
    this._inner = new SessionsStorage.Local();
  }

  public async create( secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promise<[ number, Session ]> {
    return this._inner.create( secret, validityToken );
  }

  public async verify( sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promise<Undefinedable<Session>> {
    return this._inner.verify( sessionId, secret, validityToken );
  }

  public async delete( sessionId: number, secret: Uint8Array<ArrayBuffer> ): Promise<boolean> {
    return this._inner.delete( sessionId, secret );
  }
}

class CountingVerifyStorage implements SessionsStorage {
  private readonly _inner: SessionsStorage.Local;
  public verifyCalls: number;

  public constructor() {
    this._inner = new SessionsStorage.Local();
    this.verifyCalls = 0;
  }

  public create( secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<[ number, Session ]> {
    return this._inner.create( secret, validityToken );
  }

  public verify( sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<Undefinedable<Session>> {
    this.verifyCalls++;
    return this._inner.verify( sessionId, secret, validityToken );
  }

  public delete( sessionId: number, secret: Uint8Array<ArrayBuffer> ): Promisable<boolean> {
    return this._inner.delete( sessionId, secret );
  }
}

class ThrowingDeleteStorage implements SessionsStorage {
  private readonly _inner: SessionsStorage.Local;

  public constructor() {
    this._inner = new SessionsStorage.Local();
  }

  public create( secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<[ number, Session ]> {
    return this._inner.create( secret, validityToken );
  }

  public verify( sessionId: number, secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<Undefinedable<Session>> {
    return this._inner.verify( sessionId, secret, validityToken );
  }

  public delete( _sessionId: number, _secret: Uint8Array<ArrayBuffer> ): Promisable<boolean> {
    throw new Error( 'Storage unavailable' );
  }
}

class ThrowingVerifyStorage implements SessionsStorage {
  private readonly _inner: SessionsStorage.Local;

  public constructor() {
    this._inner = new SessionsStorage.Local();
  }

  public create( secret: Uint8Array<ArrayBuffer>, validityToken: number ): Promisable<[ number, Session ]> {
    return this._inner.create( secret, validityToken );
  }

  public verify( _sessionId: number, _secret: Uint8Array<ArrayBuffer>, _validityToken: number ): Promisable<Undefinedable<Session>> {
    throw new Error( 'Storage unavailable' );
  }

  public delete( sessionId: number, secret: Uint8Array<ArrayBuffer> ): Promisable<boolean> {
    return this._inner.delete( sessionId, secret );
  }
}

function keyFromLength( length: number ): Uint8Array<ArrayBuffer> {
  const returnValue: Uint8Array<ArrayBuffer> = new Uint8Array( length );
  for( let iL1: number = 0; iL1 < length; iL1++ ) {
    returnValue[ iL1 ] = ( iL1 + 1 ) & 0xff;
  }
  return returnValue;
}

function fakeClockAt( start: number ): FakeClock {
  const realDateNow: () => number = Date.now;
  let current: number = start;
  Date.now = (): number => current;
  const returnValue: FakeClock = {
    advance( milliseconds: number ): void {
      current += milliseconds;
    },
    restore(): void {
      Date.now = realDateNow;
    }
  };
  return returnValue;
}

function cookieHeader( token: string, cookieName: string = 'session' ): string {
  return `${ cookieName }=${ token }`;
}

async function createSessionToken( app: Hono<SessionsEnv> ): Promise<string> {
  const response: Response = await app.request( '/create', { method: 'POST' } );
  const header: string | null = response.headers.get( 'set-cookie' );
  let returnValue: string;
  if( header ) {
    returnValue = tokenFromSetCookie( header );
  } else {
    throw new Error( 'Creation did not set a cookie' );
  }
  return returnValue;
}

async function verifyResponse( app: Hono<SessionsEnv>, token: string, cookieName: string = 'session' ): Promise<Response> {
  const returnValue: Response = await app.request( '/verify', { headers: { cookie: cookieHeader( token, cookieName ) } } );
  return returnValue;
}

async function isAuthenticated( app: Hono<SessionsEnv>, token: string, cookieName: string = 'session' ): Promise<boolean> {
  const response: Response = await verifyResponse( app, token, cookieName );
  const payload: { authenticated: boolean } = await jsonResponse( response );
  return payload.authenticated;
}

async function credentialFromToken( token: string, keyBytes: Uint8Array<ArrayBuffer> ): Promise<Credential> {
  const importedKey: CryptoKey = await crypto.subtle.importKey( 'raw', keyBytes, { name: 'AES-GCM' }, false, [ 'decrypt' ] );
  const bytes: Uint8Array<ArrayBuffer> = base64UrlDecode( token );
  const iv: Uint8Array<ArrayBuffer> = bytes.slice( 0, ivLength );
  const ciphertext: Uint8Array<ArrayBuffer> = bytes.slice( ivLength );
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 64
  };
  const plaintext: ArrayBuffer = await crypto.subtle.decrypt( params, importedKey, ciphertext );
  const tuple: unknown = JSON.parse( new TextDecoder( 'utf-8', { fatal: true } ).decode( plaintext ) );
  let returnValue: Credential;
  if( Array.isArray( tuple ) && ( 2 === tuple.length ) && ( 'number' === typeof tuple[ 0 ] ) && ( 'string' === typeof tuple[ 1 ] ) ) {
    returnValue = { secretText: tuple[ 1 ], sessionId: tuple[ 0 ] };
  } else {
    throw new Error( 'Malformed credential' );
  }
  return returnValue;
}

async function encryptToken( keyBytes: Uint8Array<ArrayBuffer>, plaintext: string ): Promise<string> {
  const importedKey: CryptoKey = await crypto.subtle.importKey( 'raw', keyBytes, { name: 'AES-GCM' }, false, [ 'encrypt' ] );
  const iv: Uint8Array<ArrayBuffer> = new Uint8Array( ivLength );
  crypto.getRandomValues( iv );
  const encoded: Uint8Array<ArrayBuffer> = new TextEncoder().encode( plaintext ) as Uint8Array<ArrayBuffer>;
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 64
  };
  const encrypted: ArrayBuffer = await crypto.subtle.encrypt( params, importedKey, encoded );
  const combined: Uint8Array<ArrayBuffer> = new Uint8Array( iv.length + encrypted.byteLength );
  combined.set( iv, 0 );
  combined.set( new Uint8Array( encrypted ), iv.length );
  const returnValue: string = base64UrlEncode( combined );
  return returnValue;
}

function flippedToken( token: string, index: number ): string {
  const characters: string[] = token.split( '' );
  characters[ index ] = ( 'A' === characters[ index ] ) ? 'B' : 'A';
  const returnValue: string = characters.join( '' );
  return returnValue;
}

function nonCanonicalVariants( text: string ): string[] {
  const bytes: Uint8Array<ArrayBuffer> = base64UrlDecode( text );
  const remainder: number = bytes.length % 3;
  const variants: string[] = [];
  if( 0 !== remainder ) {
    const unusedBits: number = ( 1 === remainder ) ? 4 : 2;
    const variantCount: number = ( 1 << unusedBits ) - 1;
    const lastIndex: number = base64UrlAlphabet.indexOf( text.charAt( text.length - 1 ) );
    for( let iL1: number = 1; iL1 <= variantCount; iL1++ ) {
      variants.push( text.slice( 0, text.length - 1 ) + base64UrlAlphabet.charAt( lastIndex + iL1 ) );
    }
  }
  return variants;
}

function sabotageEncrypt(): SubtleOverride {
  return overrideSubtle( ( sabotaged: SubtleCarrier ): void => {
    sabotaged.encrypt = (): Promise<ArrayBuffer> => Promise.reject( new Error( 'Encryption unavailable' ) );
  } );
}

function overrideSubtle( override: ( sabotaged: SubtleCarrier, original: Subtle ) => void ): SubtleOverride {
  const originalSubtle: Subtle = crypto.subtle;
  const ownDescriptor: Undefinedable<PropertyDescriptor> = Object.getOwnPropertyDescriptor( crypto, 'subtle' );
  const sabotagedSubtle: SubtleCarrier = Object.create( originalSubtle );
  // Native Web Crypto methods brand-check their receiver, so every method the factory touches must delegate to the original instance.
  sabotagedSubtle.encrypt = ( ...args: Parameters<Subtle[ 'encrypt' ]> ): Promise<ArrayBuffer> => originalSubtle.encrypt( ...args );
  sabotagedSubtle.decrypt = ( ...args: Parameters<Subtle[ 'decrypt' ]> ): Promise<ArrayBuffer> => originalSubtle.decrypt( ...args );
  sabotagedSubtle.importKey = ( ...args: Parameters<Subtle[ 'importKey' ]> ): Promise<CryptoKey> => originalSubtle.importKey( ...args );
  sabotagedSubtle.generateKey = ( algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[] ): Promise<CryptoKey | CryptoKeyPair> => originalSubtle.generateKey( algorithm, extractable, keyUsages );
  override( sabotagedSubtle, originalSubtle );
  Object.defineProperty( crypto, 'subtle', { value: sabotagedSubtle, configurable: true } );
  const returnValue: SubtleOverride = {
    restore(): void {
      if( ownDescriptor ) {
        Object.defineProperty( crypto, 'subtle', ownDescriptor );
      } else {
        Reflect.deleteProperty( crypto, 'subtle' );
      }
    }
  };
  return returnValue;
}

test( 'base64url helper produces canonical vectors', ( t: ExecutionContext ) => {
  t.is( base64UrlEncode( new TextEncoder().encode( 'foobar' ) as Uint8Array<ArrayBuffer> ), 'Zm9vYmFy' );
  t.is( base64UrlEncode( new Uint8Array( 0 ) ), '' );
  t.is( base64UrlEncode( new Uint8Array( [ 251, 255 ] ) ), '-_8' );
  const roundTrip: Uint8Array<ArrayBuffer> = base64UrlDecode( '-_8' );
  t.is( roundTrip.length, 2 );
  t.is( roundTrip[ 0 ], 251 );
  t.is( roundTrip[ 1 ], 255 );
} );

test( 'default creation sets the session cookie with canonical defaults', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create();
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const response: Response = await app.request( '/create', { method: 'POST' } );
  const headers: string[] = response.headers.getSetCookie();
  t.is( headers.length, 1 );
  const header: string = headers[ 0 ];
  const pair: string = cookiePairFrom( header );
  t.true( pair.startsWith( 'session=' ) );
  const token: string = tokenFromSetCookie( header );
  t.regex( token, /^[A-Za-z0-9_-]+$/ );
  t.false( token.includes( '=' ) );
  t.true( header.includes( 'HttpOnly' ) );
  t.true( header.includes( 'Secure' ) );
  t.true( header.includes( 'SameSite=Lax' ) );
  t.true( header.includes( 'Path=/' ) );
  t.true( header.includes( 'Max-Age=3600' ) );
  t.false( header.includes( 'Domain=' ) );
  t.false( header.includes( 'Partitioned' ) );
  t.false( header.includes( 'Priority=' ) );
  t.false( header.includes( 'Expires=' ) );
} );

test( 'cookie token decrypts externally to the credential tuple', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const bytes: Uint8Array<ArrayBuffer> = base64UrlDecode( token );
  t.true( ivLength < bytes.length );
  const iv: Uint8Array<ArrayBuffer> = bytes.slice( 0, ivLength );
  const ciphertext: Uint8Array<ArrayBuffer> = bytes.slice( ivLength );
  const importedKey: CryptoKey = await crypto.subtle.importKey( 'raw', key16, { name: 'AES-GCM' }, false, [ 'decrypt' ] );
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 64
  };
  const plaintext: ArrayBuffer = await crypto.subtle.decrypt( params, importedKey, ciphertext );
  const json: string = new TextDecoder( 'utf-8', { fatal: true } ).decode( plaintext );
  t.regex( json, /^\[\d+,"[A-Za-z0-9_-]+"\]$/ );
  const tuple: unknown = JSON.parse( json );
  if( Array.isArray( tuple ) && ( 2 === tuple.length ) && ( 'number' === typeof tuple[ 0 ] ) && ( 'string' === typeof tuple[ 1 ] ) ) {
    const secret: Uint8Array<ArrayBuffer> = base64UrlDecode( tuple[ 1 ] );
    t.is( secret.length, 32 );
  } else {
    t.fail( 'Credential tuple shape mismatch' );
  }
} );

test( 'a successful round trip renews the exact token cookie with default attributes', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const response: Response = await verifyResponse( app, token );
  const payload: { authenticated: boolean } = await jsonResponse( response );
  t.true( payload.authenticated );
  const headers: string[] = response.headers.getSetCookie();
  t.is( headers.length, 1 );
  const renewal: string = headers[ 0 ];
  t.is( tokenFromSetCookie( renewal ), token );
  t.true( renewal.includes( 'HttpOnly' ) );
  t.true( renewal.includes( 'Secure' ) );
  t.true( renewal.includes( 'SameSite=Lax' ) );
  t.true( renewal.includes( 'Path=/' ) );
  t.true( renewal.includes( 'Max-Age=3600' ) );
} );

test( 'malformed client tokens yield no session and clear nothing', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const validToken: string = await createSessionToken( app );
  const randomBytes: Uint8Array<ArrayBuffer> = new Uint8Array( 40 );
  crypto.getRandomValues( randomBytes );
  const malformedTokens: string[] = [
    '',
    'abc$def',
    'Zm9vYmFy==',
    'A',
    'AAAAA',
    validToken.slice( 0, validToken.length - 5 ),
    base64UrlEncode( randomBytes ),
    await encryptToken( key16, 'not json' ),
    await encryptToken( key16, '["one","two"]' ),
    await encryptToken( key16, '{"a":1}' ),
    await encryptToken( key16, '[0]' ),
    await encryptToken( key16, `[0,"${base64UrlEncode( new Uint8Array( 16 ).fill( 3 ) )}"]` )
  ];
  const cL1: number = malformedTokens.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const malformed: string = malformedTokens[ iL1 ];
    const response: Response = await verifyResponse( app, malformed );
    const payload: { authenticated: boolean } = await jsonResponse( response );
    t.false( payload.authenticated );
    assertNoSetCookie( t, response );
  }
  const missing: Response = await app.request( '/verify' );
  const missingPayload: { authenticated: boolean } = await jsonResponse( missing );
  t.false( missingPayload.authenticated );
  assertNoSetCookie( t, missing );
} );

test( 'altered iv or ciphertext fails authentication without clearing the cookie', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const alteredTokens: string[] = [
    flippedToken( token, 0 ),
    flippedToken( token, Math.floor( token.length / 2 ) ),
    flippedToken( token, token.length - 1 )
  ];
  const cL1: number = alteredTokens.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const altered: string = alteredTokens[ iL1 ];
    t.false( await isAuthenticated( app, altered ) );
    assertNoSetCookie( t, await verifyResponse( app, altered ) );
  }
} );

test( 'non-canonical byte-equivalent outer tokens are accepted', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const sessionCount: number = 11;
  let token: string = '';
  for( let iL1: number = 0; iL1 < sessionCount; iL1++ ) {
    token = await createSessionToken( app );
  }
  const variants: string[] = nonCanonicalVariants( token );
  t.true( variants.length > 0 );
  t.true( await isAuthenticated( app, token ) );
  const cL1: number = variants.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const variant: string = variants[ iL1 ];
    const response: Response = await verifyResponse( app, variant );
    const payload: { authenticated: boolean } = await jsonResponse( response );
    t.true( payload.authenticated );
    const renewalHeaders: string[] = response.headers.getSetCookie();
    t.is( renewalHeaders.length, 1 );
    t.is( tokenFromSetCookie( renewalHeaders[ 0 ] ), variant );
    t.true( renewalHeaders[ 0 ].includes( 'Max-Age=3600' ) );
  }
} );

test( 'non-canonical byte-equivalent embedded secrets are accepted', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const credential: Credential = await credentialFromToken( token, key16 );
  const variants: string[] = nonCanonicalVariants( credential.secretText );
  t.true( variants.length > 0 );
  const cL1: number = variants.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const variant: string = variants[ iL1 ];
    const forged: string = await encryptToken( key16, JSON.stringify( [ credential.sessionId, variant ] ) );
    const response: Response = await verifyResponse( app, forged );
    const payload: { authenticated: boolean } = await jsonResponse( response );
    t.true( payload.authenticated );
    const renewalHeaders: string[] = response.headers.getSetCookie();
    t.is( renewalHeaders.length, 1 );
    t.is( tokenFromSetCookie( renewalHeaders[ 0 ] ), forged );
  }
  t.true( await isAuthenticated( app, token ) );
} );

test( 'a whitespace-wrapped credential plaintext yields no session without storage verification', async ( t: ExecutionContext ) => {
  const storage: CountingVerifyStorage = new CountingVerifyStorage();
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const credential: Credential = await credentialFromToken( token, key16 );
  const forged: string = await encryptToken( key16, `[ ${credential.sessionId},"${credential.secretText}" ]` );
  const verifyCallsBefore: number = storage.verifyCalls;
  const response: Response = await verifyResponse( app, forged );
  const payload: { authenticated: boolean } = await jsonResponse( response );
  t.false( payload.authenticated );
  assertNoSetCookie( t, response );
  t.is( storage.verifyCalls, verifyCallsBefore );
} );

test( 'a leading UTF-8 BOM in the credential plaintext yields no session without storage verification', async ( t: ExecutionContext ) => {
  const storage: CountingVerifyStorage = new CountingVerifyStorage();
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const credential: Credential = await credentialFromToken( token, key16 );
  const forged: string = await encryptToken( key16, '\uFEFF' + JSON.stringify( [ credential.sessionId, credential.secretText ] ) );
  const verifyCallsBefore: number = storage.verifyCalls;
  const response: Response = await verifyResponse( app, forged );
  const payload: { authenticated: boolean } = await jsonResponse( response );
  t.false( payload.authenticated );
  assertNoSetCookie( t, response );
  t.is( storage.verifyCalls, verifyCallsBefore );
} );

test( 'an alternate numeric spelling of the session id yields no session without storage verification', async ( t: ExecutionContext ) => {
  const storage: CountingVerifyStorage = new CountingVerifyStorage();
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  await createSessionToken( app );
  const token: string = await createSessionToken( app );
  const credential: Credential = await credentialFromToken( token, key16 );
  t.is( credential.sessionId, 1 );
  const forged: string = await encryptToken( key16, `[1e0,"${credential.secretText}"]` );
  const verifyCallsBefore: number = storage.verifyCalls;
  const response: Response = await verifyResponse( app, forged );
  const payload: { authenticated: boolean } = await jsonResponse( response );
  t.false( payload.authenticated );
  assertNoSetCookie( t, response );
  t.is( storage.verifyCalls, verifyCallsBefore );
} );

test( 'credential session IDs outside the storage contract are rejected before storage verification', async ( t: ExecutionContext ) => {
  const storage: CountingVerifyStorage = new CountingVerifyStorage();
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const invalidSessionIds: number[] = [ -1, 1.5, Number.MAX_SAFE_INTEGER + 1 ];
  const verifyCallsBefore: number = storage.verifyCalls;
  const cL1: number = invalidSessionIds.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const invalidSessionId: number = invalidSessionIds[ iL1 ];
    const token: string = await encryptToken( key16, JSON.stringify( [ invalidSessionId, secretTextOther ] ) );
    const response: Response = await verifyResponse( app, token );
    const payload: { authenticated: boolean } = await jsonResponse( response );
    t.false( payload.authenticated );
    assertNoSetCookie( t, response );
  }
  t.is( storage.verifyCalls, verifyCallsBefore );
} );

test( 'a wrong stored secret verifies to nothing and leaves the record intact', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const credential: Credential = await credentialFromToken( token, key16 );
  const forged: string = await encryptToken( key16, JSON.stringify( [ credential.sessionId, secretTextOther ] ) );
  const forgedResponse: Response = await verifyResponse( app, forged );
  const forgedPayload: { authenticated: boolean } = await jsonResponse( forgedResponse );
  t.false( forgedPayload.authenticated );
  assertNoSetCookie( t, forgedResponse );
  t.true( await isAuthenticated( app, token ) );
} );

test.serial( 'at exact deadline verification returns no session and deletes the record', async ( t: ExecutionContext ) => {
  const clock: FakeClock = fakeClockAt( 1_000 );
  try {
    const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, validityToken: 100 } );
    const app: Hono<SessionsEnv> = createTestApp( manager );
    const firstToken: string = await createSessionToken( app );
    const firstCredential: Credential = await credentialFromToken( firstToken, key16 );
    clock.advance( 100 );
    const expiredResponse: Response = await verifyResponse( app, firstToken );
    const expiredPayload: { authenticated: boolean } = await jsonResponse( expiredResponse );
    t.false( expiredPayload.authenticated );
    assertNoSetCookie( t, expiredResponse );
    const secondToken: string = await createSessionToken( app );
    const secondCredential: Credential = await credentialFromToken( secondToken, key16 );
    t.is( secondCredential.sessionId, firstCredential.sessionId );
  } finally {
    clock.restore();
  }
} );

test.serial( 'successful verification slides expiry past the original deadline', async ( t: ExecutionContext ) => {
  const clock: FakeClock = fakeClockAt( 1_000 );
  try {
    const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, validityToken: 100 } );
    const app: Hono<SessionsEnv> = createTestApp( manager );
    const token: string = await createSessionToken( app );
    clock.advance( 50 );
    t.true( await isAuthenticated( app, token ) );
    const renewal: Response = await verifyResponse( app, token );
    const renewalHeaders: string[] = renewal.headers.getSetCookie();
    t.is( renewalHeaders.length, 1 );
    t.true( renewalHeaders[ 0 ].includes( 'Max-Age=1' ) );
    clock.advance( 60 );
    t.true( await isAuthenticated( app, token ) );
    clock.advance( 100 );
    t.false( await isAuthenticated( app, token ) );
  } finally {
    clock.restore();
  }
} );

test( 'logout removes the session and clears the cookie and context session', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const logout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( token ) } } );
  const payload: { cleared: boolean; deleted: boolean } = await jsonResponse( logout );
  t.true( payload.deleted );
  t.true( payload.cleared );
  const headers: string[] = logout.headers.getSetCookie();
  t.is( headers.length, 2 );
  const renewal: string = headers[ 0 ];
  const deletion: string = headers[ 1 ];
  t.is( tokenFromSetCookie( renewal ), token );
  t.true( renewal.includes( 'Max-Age=3600' ) );
  t.true( cookiePairFrom( deletion ).startsWith( 'session=' ) );
  t.true( deletion.includes( 'Max-Age=0' ) );
  t.false( await isAuthenticated( app, token ) );
} );

test( 'logout with a malformed token still clears the cookie', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  await createSessionToken( app );
  const logout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: 'session=###bad' } } );
  const payload: { cleared: boolean; deleted: boolean } = await jsonResponse( logout );
  t.false( payload.deleted );
  t.true( payload.cleared );
  const headers: string[] = logout.headers.getSetCookie();
  t.is( headers.length, 1 );
  t.true( headers[ 0 ].includes( 'Max-Age=0' ) );
} );

test( 'create after a valid cookie renews the old token first and issues a new token last', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const oldToken: string = await createSessionToken( app );
  const response: Response = await app.request( '/create', { method: 'POST', headers: { cookie: cookieHeader( oldToken ) } } );
  const headers: string[] = response.headers.getSetCookie();
  t.is( headers.length, 2 );
  const renewal: string = headers[ 0 ];
  const created: string = headers[ 1 ];
  t.is( tokenFromSetCookie( renewal ), oldToken );
  t.true( renewal.includes( 'Max-Age=3600' ) );
  t.not( tokenFromSetCookie( created ), oldToken );
  t.true( created.includes( 'Max-Age=3600' ) );
} );

test( 'storage deletion failure propagates without a removal cookie', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage: new ThrowingDeleteStorage() } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const captureApp: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  let captured: Undefinedable<Context<SessionsEnv>>;
  captureApp.get( '/capture', ( context: Context<SessionsEnv> ): Response => {
    captured = context;
    return context.text( 'ok' );
  } );
  await captureApp.request( '/capture' );
  if( captured ) {
    const capturedContext: Context<SessionsEnv> = captured;
    await t.throwsAsync( (): Promise<boolean> => manager.delete( capturedContext, token ), { message: 'Storage unavailable' } );
    t.is( capturedContext.res.headers.get( 'set-cookie' ), null );
  } else {
    t.fail( 'Context capture failed' );
  }
} );

test( 'direct verify renews the token cookie and a later malformed verify adds nothing', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const captureApp: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  let captured: Undefinedable<Context<SessionsEnv>>;
  captureApp.get( '/capture', ( context: Context<SessionsEnv> ): Response => {
    captured = context;
    return context.text( 'ok' );
  } );
  await captureApp.request( '/capture' );
  if( captured ) {
    const capturedContext: Context<SessionsEnv> = captured;
    const session: Undefinedable<Session> = await manager.verify( capturedContext, token );
    if( session ) {
      t.is( capturedContext.get( 'session' ), session );
      const renewalHeaders: string[] = capturedContext.res.headers.getSetCookie();
      t.is( renewalHeaders.length, 1 );
      t.is( tokenFromSetCookie( renewalHeaders[ 0 ] ), token );
      const malformed: Undefinedable<Session> = await manager.verify( capturedContext, '###bad' );
      t.is( malformed, undefined );
      t.is( capturedContext.get( 'session' ), undefined );
      t.is( capturedContext.res.headers.getSetCookie().length, 1 );
    } else {
      t.fail( 'Valid verification must return a session' );
    }
  } else {
    t.fail( 'Context capture failed' );
  }
} );

test( 'storage verification failure propagates without setting a cookie', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage: new ThrowingVerifyStorage() } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const captureApp: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  let captured: Undefinedable<Context<SessionsEnv>>;
  captureApp.get( '/capture', ( context: Context<SessionsEnv> ): Response => {
    captured = context;
    return context.text( 'ok' );
  } );
  await captureApp.request( '/capture' );
  if( captured ) {
    const capturedContext: Context<SessionsEnv> = captured;
    await t.throwsAsync( (): Promise<Undefinedable<Session>> => manager.verify( capturedContext, token ), { message: 'Storage unavailable' } );
    t.is( capturedContext.get( 'session' ), undefined );
    t.is( capturedContext.res.headers.get( 'set-cookie' ), null );
  } else {
    t.fail( 'Context capture failed' );
  }
} );

test( 'renewal serialization failure propagates without a session or header', async ( t: ExecutionContext ) => {
  const storage: SessionsStorage.Local = new SessionsStorage.Local();
  const issuer: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const issuerApp: Hono<SessionsEnv> = createTestApp( issuer );
  const token: string = await createSessionToken( issuerApp );
  const verifier: SessionsManager = await SessionsManager.create( { cookie: { path: '/bad;path' }, encryptionKey: key16, storage } );
  const captureApp: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  let captured: Undefinedable<Context<SessionsEnv>>;
  captureApp.get( '/capture', ( context: Context<SessionsEnv> ): Response => {
    captured = context;
    return context.text( 'ok' );
  } );
  await captureApp.request( '/capture' );
  if( captured ) {
    const capturedContext: Context<SessionsEnv> = captured;
    await t.throwsAsync( (): Promise<Undefinedable<Session>> => verifier.verify( capturedContext, token ), { message: 'path must not contain ";", "\\r", or "\\n"' } );
    t.is( capturedContext.get( 'session' ), undefined );
    t.is( capturedContext.res.headers.getSetCookie().length, 0 );
  } else {
    t.fail( 'Context capture failed' );
  }
} );

test( 'id reuse with maxSessions one invalidates the old credential', async ( t: ExecutionContext ) => {
  const storage: SessionsStorage.Local = new SessionsStorage.Local();
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const firstToken: string = await createSessionToken( app );
  const firstCredential: Credential = await credentialFromToken( firstToken, key16 );
  const logoutFirst: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( firstToken ) } } );
  const firstPayload: { cleared: boolean; deleted: boolean } = await jsonResponse( logoutFirst );
  t.true( firstPayload.deleted );
  const secondToken: string = await createSessionToken( app );
  const secondCredential: Credential = await credentialFromToken( secondToken, key16 );
  t.is( secondCredential.sessionId, firstCredential.sessionId );
  const invalidatedResponse: Response = await verifyResponse( app, firstToken );
  const invalidatedPayload: { authenticated: boolean } = await jsonResponse( invalidatedResponse );
  t.false( invalidatedPayload.authenticated );
  assertNoSetCookie( t, invalidatedResponse );
  t.true( await isAuthenticated( app, secondToken ) );
  const forgedLogout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( firstToken ) } } );
  const forgedPayload: { cleared: boolean; deleted: boolean } = await jsonResponse( forgedLogout );
  t.false( forgedPayload.deleted );
  t.true( forgedPayload.cleared );
  const logoutSecond: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( secondToken ) } } );
  const secondPayload: { cleared: boolean; deleted: boolean } = await jsonResponse( logoutSecond );
  t.true( secondPayload.deleted );
  t.true( secondPayload.cleared );
} );

test( 'ten concurrent requests with one token all authenticate', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const requests: Promise<boolean>[] = [];
  for( let iL1: number = 0; iL1 < 10; iL1++ ) {
    requests.push( isAuthenticated( app, token ) );
  }
  const results: boolean[] = await Promise.all( requests );
  t.deepEqual( results, [ true, true, true, true, true, true, true, true, true, true ] );
} );

test( 'two conceptual tabs interleave data operations on one session', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  const header: Record<string, string> = { 'content-type': 'application/json', cookie: cookieHeader( token ) };
  const writes: Promise<Response>[] = [
    Promise.resolve( app.request( '/set/tab', { method: 'POST', headers: header, body: JSON.stringify( { tab: 1 } ) } ) ),
    Promise.resolve( app.request( '/set/note', { method: 'POST', headers: header, body: JSON.stringify( 'hello' ) } ) ),
    Promise.resolve( app.request( '/get/tab', { headers: { cookie: cookieHeader( token ) } } ) ),
    Promise.resolve( app.request( '/verify', { headers: { cookie: cookieHeader( token ) } } ) )
  ];
  const settled: Response[] = await Promise.all( writes );
  const cL1: number = settled.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const settledResponse: Response = settled[ iL1 ];
    t.true( settledResponse.ok );
  }
  const readTab: Response = await app.request( '/get/tab', { headers: { cookie: cookieHeader( token ) } } );
  const tabPayload: { value: JSONValue } = await jsonResponse( readTab );
  t.deepEqual( tabPayload.value, { tab: 1 } );
  const readNote: Response = await app.request( '/get/note', { headers: { cookie: cookieHeader( token ) } } );
  const notePayload: { value: JSONValue } = await jsonResponse( readNote );
  t.is( notePayload.value, 'hello' );
} );

test( 'async custom storage drives the same flow', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage: new AsyncSessionsStorage() } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  t.true( await isAuthenticated( app, token ) );
  await app.request( '/set/marker', { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader( token ) }, body: JSON.stringify( 'ok' ) } );
  const read: Response = await app.request( '/get/marker', { headers: { cookie: cookieHeader( token ) } } );
  const payload: { value: JSONValue } = await jsonResponse( read );
  t.is( payload.value, 'ok' );
  const logout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( token ) } } );
  const logoutPayload: { cleared: boolean; deleted: boolean } = await jsonResponse( logout );
  t.true( logoutPayload.deleted );
  t.true( logoutPayload.cleared );
} );

test( 'separate generated keys cannot cross verify and keep working alone', async ( t: ExecutionContext ) => {
  const first: SessionsManager = await SessionsManager.create();
  const second: SessionsManager = await SessionsManager.create();
  const firstApp: Hono<SessionsEnv> = createTestApp( first );
  const secondApp: Hono<SessionsEnv> = createTestApp( second );
  const token: string = await createSessionToken( firstApp );
  t.false( await isAuthenticated( secondApp, token ) );
  t.true( await isAuthenticated( firstApp, token ) );
} );

test( 'the same supplied key and storage interoperate', async ( t: ExecutionContext ) => {
  const storage: SessionsStorage.Local = new SessionsStorage.Local();
  const first: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const second: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const firstApp: Hono<SessionsEnv> = createTestApp( first );
  const secondApp: Hono<SessionsEnv> = createTestApp( second );
  const token: string = await createSessionToken( firstApp );
  t.true( await isAuthenticated( secondApp, token ) );
} );

test( 'a custom cookie name drives creation, lookup, renewal, and deletion', async ( t: ExecutionContext ) => {
  const cookieName: string = 'app.sid';
  const manager: SessionsManager = await SessionsManager.create( { cookie: { name: cookieName }, encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager, cookieName );
  const created: Response = await app.request( '/create', { method: 'POST' } );
  const createdHeaders: string[] = created.headers.getSetCookie();
  t.is( createdHeaders.length, 1 );
  const createdHeader: string = createdHeaders[ 0 ];
  t.true( cookiePairFrom( createdHeader ).startsWith( 'app.sid=' ) );
  const token: string = tokenFromSetCookie( createdHeader );
  const renewed: Response = await verifyResponse( app, token, cookieName );
  const renewedPayload: { authenticated: boolean } = await jsonResponse( renewed );
  t.true( renewedPayload.authenticated );
  const renewedHeaders: string[] = renewed.headers.getSetCookie();
  t.is( renewedHeaders.length, 1 );
  const renewal: string = renewedHeaders[ 0 ];
  t.is( tokenFromSetCookie( renewal ), token );
  t.true( cookiePairFrom( renewal ).startsWith( 'app.sid=' ) );
  const logout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( token, cookieName ) } } );
  const logoutPayload: { cleared: boolean; deleted: boolean } = await jsonResponse( logout );
  t.true( logoutPayload.deleted );
  t.true( logoutPayload.cleared );
  const logoutHeaders: string[] = logout.headers.getSetCookie();
  t.is( logoutHeaders.length, 2 );
  const logoutRenewal: string = logoutHeaders[ 0 ];
  const deletion: string = logoutHeaders[ 1 ];
  t.is( tokenFromSetCookie( logoutRenewal ), token );
  t.true( cookiePairFrom( logoutRenewal ).startsWith( 'app.sid=' ) );
  t.true( cookiePairFrom( deletion ).startsWith( 'app.sid=' ) );
  t.true( deletion.includes( 'Max-Age=0' ) );
  const afterLogout: Response = await verifyResponse( app, token, cookieName );
  const afterLogoutPayload: { authenticated: boolean } = await jsonResponse( afterLogout );
  t.false( afterLogoutPayload.authenticated );
  assertNoSetCookie( t, afterLogout );
} );

test( 'a custom-named manager ignores its token under the default cookie name', async ( t: ExecutionContext ) => {
  const cookieName: string = 'app.sid';
  const manager: SessionsManager = await SessionsManager.create( { cookie: { name: cookieName }, encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager, cookieName );
  const token: string = await createSessionToken( app );
  const response: Response = await verifyResponse( app, token );
  const payload: { authenticated: boolean } = await jsonResponse( response );
  t.false( payload.authenticated );
  assertNoSetCookie( t, response );
} );

test( 'managers with different cookie names read only their configured name', async ( t: ExecutionContext ) => {
  const storage: SessionsStorage.Local = new SessionsStorage.Local();
  const first: SessionsManager = await SessionsManager.create( { cookie: { name: 'first.sid' }, encryptionKey: key16, storage } );
  const second: SessionsManager = await SessionsManager.create( { cookie: { name: 'second.sid' }, encryptionKey: key16, storage } );
  const firstApp: Hono<SessionsEnv> = createTestApp( first, 'first.sid' );
  const secondApp: Hono<SessionsEnv> = createTestApp( second, 'second.sid' );
  const token: string = await createSessionToken( firstApp );
  // Cookie-name isolation is lookup isolation, not cryptographic isolation: the shared key and storage let the second manager read the token once it arrives under the second name.
  const underFirst: Response = await verifyResponse( secondApp, token, 'first.sid' );
  const underFirstPayload: { authenticated: boolean } = await jsonResponse( underFirst );
  t.false( underFirstPayload.authenticated );
  assertNoSetCookie( t, underFirst );
  const underSecond: Response = await verifyResponse( secondApp, token, 'second.sid' );
  const underSecondPayload: { authenticated: boolean } = await jsonResponse( underSecond );
  t.true( underSecondPayload.authenticated );
  const renewalHeaders: string[] = underSecond.headers.getSetCookie();
  t.is( renewalHeaders.length, 1 );
  const renewal: string = renewalHeaders[ 0 ];
  t.is( tokenFromSetCookie( renewal ), token );
  t.true( cookiePairFrom( renewal ).startsWith( 'second.sid=' ) );
} );

test( 'a 32-byte supplied key creates and verifies a session without algorithm configuration', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key32 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  t.true( await isAuthenticated( app, token ) );
  const credential: Credential = await credentialFromToken( token, key32 );
  t.true( Number.isSafeInteger( credential.sessionId ) );
  t.true( 0 <= credential.sessionId );
} );

test( 'a 24-byte supplied key creates and verifies a session without algorithm configuration', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key24 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  t.true( await isAuthenticated( app, token ) );
  const credential: Credential = await credentialFromToken( token, key24 );
  t.true( Number.isSafeInteger( credential.sessionId ) );
  t.true( 0 <= credential.sessionId );
} );

test.serial( 'creation generates exactly one AES-128 key and reuses it for the manager lifetime', async ( t: ExecutionContext ) => {
  const generateCalls: GenerateKeyCall[] = [];
  const sabotage: SubtleOverride = overrideSubtle( ( sabotaged: SubtleCarrier, original: Subtle ): void => {
    sabotaged.generateKey = ( algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[] ): Promise<CryptoKey | CryptoKeyPair> => {
      generateCalls.push( { algorithm, extractable, keyUsages } );
      return original.generateKey( algorithm, extractable, keyUsages );
    };
  } );
  try {
    const manager: SessionsManager = await SessionsManager.create();
    t.deepEqual( generateCalls, [ { algorithm: { name: 'AES-GCM', length: 128 }, extractable: false, keyUsages: [ 'encrypt', 'decrypt' ] } ] );
    const app: Hono<SessionsEnv> = createTestApp( manager );
    const firstToken: string = await createSessionToken( app );
    t.true( await isAuthenticated( app, firstToken ) );
    const secondToken: string = await createSessionToken( app );
    t.true( await isAuthenticated( app, secondToken ) );
    t.is( generateCalls.length, 1 );
  } finally {
    sabotage.restore();
  }
} );

test( 'invalid key length rejects the factory', async ( t: ExecutionContext ) => {
  const shortKey: Uint8Array<ArrayBuffer> = keyFromLength( 15 );
  await t.throwsAsync( SessionsManager.create( { encryptionKey: shortKey } ) );
} );

test( 'cookie modes map to the canonical SameSite and Partitioned attributes', async ( t: ExecutionContext ) => {
  const cases: CookieModeCase[] = [
    { mode: 'strict', partitioned: false, sameSite: 'SameSite=Strict' },
    { mode: 'lax', partitioned: false, sameSite: 'SameSite=Lax' },
    { mode: 'cross-site', partitioned: false, sameSite: 'SameSite=None' },
    { mode: 'partitioned', partitioned: true, sameSite: 'SameSite=None' }
  ];
  const cL1: number = cases.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const cookieCase: CookieModeCase = cases[ iL1 ];
    const manager: SessionsManager = await SessionsManager.create( { cookie: { mode: cookieCase.mode }, encryptionKey: key16 } );
    const app: Hono<SessionsEnv> = createTestApp( manager );
    const response: Response = await app.request( '/create', { method: 'POST' } );
    const headers: string[] = response.headers.getSetCookie();
    t.is( headers.length, 1 );
    const header: string = headers[ 0 ];
    t.true( header.includes( cookieCase.sameSite ) );
    t.is( header.includes( 'Partitioned' ), cookieCase.partitioned );
    t.true( header.includes( 'Secure' ) );
    t.true( header.includes( 'HttpOnly' ) );
  }
} );

test( 'partitioned cookies keep their attributes on creation, renewal, and deletion', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { cookie: { domain: 'example.com', mode: 'partitioned', path: '/auth' }, encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const created: Response = await app.request( '/create', { method: 'POST' } );
  const createdHeaders: string[] = created.headers.getSetCookie();
  t.is( createdHeaders.length, 1 );
  const createdHeader: string = createdHeaders[ 0 ];
  t.true( createdHeader.includes( 'Partitioned' ) );
  t.true( createdHeader.includes( 'SameSite=None' ) );
  t.true( createdHeader.includes( 'Secure' ) );
  t.true( createdHeader.includes( 'Domain=example.com' ) );
  t.true( createdHeader.includes( 'Path=/auth' ) );
  const token: string = tokenFromSetCookie( createdHeader );
  const logout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( token ) } } );
  const logoutHeaders: string[] = logout.headers.getSetCookie();
  t.is( logoutHeaders.length, 2 );
  const renewal: string = logoutHeaders[ 0 ];
  t.is( tokenFromSetCookie( renewal ), token );
  t.true( renewal.includes( 'HttpOnly' ) );
  t.true( renewal.includes( 'SameSite=None' ) );
  t.true( renewal.includes( 'Partitioned' ) );
  t.true( renewal.includes( 'Secure' ) );
  t.true( renewal.includes( 'Domain=example.com' ) );
  t.true( renewal.includes( 'Path=/auth' ) );
  t.true( renewal.includes( 'Max-Age=3600' ) );
  t.false( renewal.includes( 'Expires=' ) );
  const deletion: string = logoutHeaders[ 1 ];
  t.true( deletion.includes( 'Partitioned' ) );
  t.true( deletion.includes( 'SameSite=None' ) );
  t.true( deletion.includes( 'Secure' ) );
  t.true( deletion.includes( 'Domain=example.com' ) );
  t.true( deletion.includes( 'Path=/auth' ) );
  t.true( deletion.includes( 'Max-Age=0' ) );
} );

test( 'cookie options set to undefined keep the canonical defaults', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { cookie: { domain: undefined, mode: undefined, name: undefined, path: undefined, secure: undefined }, encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const response: Response = await app.request( '/create', { method: 'POST' } );
  const headers: string[] = response.headers.getSetCookie();
  t.is( headers.length, 1 );
  const header: string = headers[ 0 ];
  t.true( cookiePairFrom( header ).startsWith( 'session=' ) );
  t.true( header.includes( 'HttpOnly' ) );
  t.true( header.includes( 'Secure' ) );
  t.true( header.includes( 'SameSite=Lax' ) );
  t.true( header.includes( 'Path=/' ) );
  t.true( header.includes( 'Max-Age=3600' ) );
  t.false( header.includes( 'Domain=' ) );
  t.false( header.includes( 'Partitioned' ) );
} );

test( 'secure false is allowed for strict and lax and keeps HttpOnly without Secure', async ( t: ExecutionContext ) => {
  const modes: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'mode' ]>[] = [ 'strict', 'lax' ];
  const cL1: number = modes.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const mode: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'mode' ]> = modes[ iL1 ];
    const manager: SessionsManager = await SessionsManager.create( { cookie: { mode, secure: false }, encryptionKey: key16 } );
    const app: Hono<SessionsEnv> = createTestApp( manager );
    const response: Response = await app.request( '/create', { method: 'POST' } );
    const headers: string[] = response.headers.getSetCookie();
    t.is( headers.length, 1 );
    const header: string = headers[ 0 ];
    t.false( header.includes( 'Secure' ) );
    t.true( header.includes( 'HttpOnly' ) );
    t.true( header.includes( 'Path=/' ) );
    t.true( header.includes( 'Max-Age=3600' ) );
  }
} );

test( 'the supplied key is copied before import', async ( t: ExecutionContext ) => {
  const keyBytes: Uint8Array<ArrayBuffer> = keyFromLength( 16 );
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: keyBytes } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const token: string = await createSessionToken( app );
  keyBytes.fill( 0 );
  t.true( await isAuthenticated( app, token ) );
} );

test.serial( 'an issuance failure cleans up the created record', async ( t: ExecutionContext ) => {
  const storage: SessionsStorage.Local = new SessionsStorage.Local();
  const brokenManager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
  const captureApp: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  let captured: Undefinedable<Context<SessionsEnv>>;
  captureApp.get( '/capture', ( context: Context<SessionsEnv> ): Response => {
    captured = context;
    return context.text( 'ok' );
  } );
  await captureApp.request( '/capture' );
  if( captured ) {
    const capturedContext: Context<SessionsEnv> = captured;
    const sabotage: SubtleOverride = sabotageEncrypt();
    try {
      await t.throwsAsync( (): Promise<Session> => brokenManager.create( capturedContext ), { message: 'Encryption unavailable' } );
    } finally {
      sabotage.restore();
    }
    t.is( capturedContext.res.headers.get( 'set-cookie' ), null );
    const healthyManager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage } );
    const healthyApp: Hono<SessionsEnv> = createTestApp( healthyManager );
    const token: string = await createSessionToken( healthyApp );
    const credential: Credential = await credentialFromToken( token, key16 );
    t.is( credential.sessionId, 0 );
  } else {
    t.fail( 'Context capture failed' );
  }
} );

test.serial( 'an issuance failure still rethrows its own error when cleanup also fails', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16, storage: new ThrowingDeleteStorage() } );
  const captureApp: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  let captured: Undefinedable<Context<SessionsEnv>>;
  captureApp.get( '/capture', ( context: Context<SessionsEnv> ): Response => {
    captured = context;
    return context.text( 'ok' );
  } );
  await captureApp.request( '/capture' );
  if( captured ) {
    const capturedContext: Context<SessionsEnv> = captured;
    const sabotage: SubtleOverride = sabotageEncrypt();
    try {
      await t.throwsAsync( (): Promise<Session> => manager.create( capturedContext ), { message: 'Encryption unavailable' } );
    } finally {
      sabotage.restore();
    }
    t.is( capturedContext.res.headers.get( 'set-cookie' ), null );
  } else {
    t.fail( 'Context capture failed' );
  }
} );

test( 'tokens that decode to a short buffer yield no session', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const shortTokens: string[] = [
    base64UrlEncode( new Uint8Array( 12 ) ),
    base64UrlEncode( new Uint8Array( 4 ) )
  ];
  const cL1: number = shortTokens.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const short: string = shortTokens[ iL1 ];
    t.false( await isAuthenticated( app, short ) );
    assertNoSetCookie( t, await verifyResponse( app, short ) );
  }
} );

test( 'invalid validityToken rejects the factory', async ( t: ExecutionContext ) => {
  await t.throwsAsync( SessionsManager.create( { validityToken: 0 } ), { message: 'validityToken must be a positive safe integer' } );
  await t.throwsAsync( SessionsManager.create( { validityToken: 1.5 } ), { message: 'validityToken must be a positive safe integer' } );
} );

test( 'invalid cookie paths reject the factory', async ( t: ExecutionContext ) => {
  const expectedMessage: string = 'cookie.path must be a non-empty absolute path starting with /';
  await t.throwsAsync( SessionsManager.create( { cookie: { path: '' } } ), { message: expectedMessage } );
  await t.throwsAsync( SessionsManager.create( { cookie: { path: 'auth' } } ), { message: expectedMessage } );
} );

test( 'invalid cookie names reject the factory before key work', async ( t: ExecutionContext ) => {
  const expectedMessage: string = 'cookie.name must be a valid cookie name';
  const invalidNames: string[] = [ '', 'bad;name', 'bad name', 'bad\tname', 'bad\rname', 'bad\nname', 'bad\u0000name', 'bad=name', 'bad,name', 'bad/name' ];
  const cL1: number = invalidNames.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const invalidName: string = invalidNames[ iL1 ];
    await t.throwsAsync( SessionsManager.create( { cookie: { name: invalidName } } ), { message: expectedMessage } );
  }
  const shortKey: Uint8Array<ArrayBuffer> = keyFromLength( 15 );
  await t.throwsAsync( SessionsManager.create( { cookie: { name: '' }, encryptionKey: shortKey } ), { message: expectedMessage } );
} );

test( 'derived Max-Age follows the validityToken in whole seconds', async ( t: ExecutionContext ) => {
  const cases: MaxAgeCase[] = [
    { maxAge: 1, validityToken: 1 },
    { maxAge: 1, validityToken: 1000 },
    { maxAge: 2, validityToken: 1001 },
    { maxAge: 3600, validityToken: 3_600_000 }
  ];
  const cL1: number = cases.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const maxAgeCase: MaxAgeCase = cases[ iL1 ];
    const manager: SessionsManager = await SessionsManager.create( { validityToken: maxAgeCase.validityToken, encryptionKey: key16 } );
    const app: Hono<SessionsEnv> = createTestApp( manager );
    const response: Response = await app.request( '/create', { method: 'POST' } );
    const headers: string[] = response.headers.getSetCookie();
    t.is( headers.length, 1 );
    const header: string = headers[ 0 ];
    t.true( header.includes( `Max-Age=${ maxAgeCase.maxAge }` ) );
    t.false( header.includes( 'Expires=' ) );
  }
} );

test( 'the maximum validityToken is accepted and one millisecond more is rejected', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { validityToken: 34_560_000_000, encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const response: Response = await app.request( '/create', { method: 'POST' } );
  const headers: string[] = response.headers.getSetCookie();
  t.is( headers.length, 1 );
  t.true( headers[ 0 ].includes( 'Max-Age=34560000' ) );
  await t.throwsAsync( SessionsManager.create( { validityToken: 34_560_000_001 } ), { message: 'validityToken must not exceed 34560000000 milliseconds (400 days)' } );
} );

test( 'cross-site and partitioned modes reject secure false at the factory', async ( t: ExecutionContext ) => {
  const modes: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'mode' ]>[] = [ 'cross-site', 'partitioned' ];
  const expectedMessage: string = "cookie.mode 'cross-site' and 'partitioned' require cookie.secure to be true";
  const cL1: number = modes.length;
  for( let iL1: number = 0; iL1 < cL1; iL1++ ) {
    const mode: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'mode' ]> = modes[ iL1 ];
    await t.throwsAsync( SessionsManager.create( { cookie: { mode, secure: false } } ), { message: expectedMessage } );
  }
} );

test( 'a configured domain and path appear on creation, renewal, and deletion without Expires', async ( t: ExecutionContext ) => {
  const manager: SessionsManager = await SessionsManager.create( { cookie: { domain: 'example.com', path: '/auth' }, encryptionKey: key16 } );
  const app: Hono<SessionsEnv> = createTestApp( manager );
  const created: Response = await app.request( '/create', { method: 'POST' } );
  const createdHeaders: string[] = created.headers.getSetCookie();
  t.is( createdHeaders.length, 1 );
  const createdHeader: string = createdHeaders[ 0 ];
  t.true( createdHeader.includes( 'Domain=example.com' ) );
  t.true( createdHeader.includes( 'Path=/auth' ) );
  t.true( createdHeader.includes( 'Max-Age=3600' ) );
  t.true( createdHeader.includes( 'Secure' ) );
  t.false( createdHeader.includes( 'Expires=' ) );
  const token: string = tokenFromSetCookie( createdHeader );
  const verified: Response = await verifyResponse( app, token );
  const verifiedHeaders: string[] = verified.headers.getSetCookie();
  t.is( verifiedHeaders.length, 1 );
  const verifiedHeader: string = verifiedHeaders[ 0 ];
  t.true( verifiedHeader.includes( 'Domain=example.com' ) );
  t.true( verifiedHeader.includes( 'Path=/auth' ) );
  t.true( verifiedHeader.includes( 'Max-Age=3600' ) );
  t.true( verifiedHeader.includes( 'Secure' ) );
  t.false( verifiedHeader.includes( 'Expires=' ) );
  const logout: Response = await app.request( '/logout', { method: 'POST', headers: { cookie: cookieHeader( token ) } } );
  const logoutHeaders: string[] = logout.headers.getSetCookie();
  t.is( logoutHeaders.length, 2 );
  const deletion: string = logoutHeaders[ 1 ];
  t.true( deletion.includes( 'Domain=example.com' ) );
  t.true( deletion.includes( 'Path=/auth' ) );
  t.true( deletion.includes( 'Max-Age=0' ) );
  t.true( deletion.includes( 'Secure' ) );
  t.false( deletion.includes( 'Expires=' ) );
} );

test.serial( 'subtle overrides restore the exact pre-override property state of crypto.subtle', ( t: ExecutionContext ): void => {
  const absentDescriptor: Undefinedable<PropertyDescriptor> = Object.getOwnPropertyDescriptor( crypto, 'subtle' );
  const sabotage: SubtleOverride = sabotageEncrypt();
  const sabotagedDescriptor: Undefinedable<PropertyDescriptor> = Object.getOwnPropertyDescriptor( crypto, 'subtle' );
  sabotage.restore();
  t.truthy( sabotagedDescriptor );
  t.deepEqual( Object.getOwnPropertyDescriptor( crypto, 'subtle' ), absentDescriptor );
  const fixtureDescriptor: Undefinedable<PropertyDescriptor> = Object.getOwnPropertyDescriptor( crypto, 'subtle' );
  try {
    Object.defineProperty( crypto, 'subtle', { value: crypto.subtle, configurable: true } );
    const installedDescriptor: Undefinedable<PropertyDescriptor> = Object.getOwnPropertyDescriptor( crypto, 'subtle' );
    const override: SubtleOverride = overrideSubtle( ( sabotaged: SubtleCarrier, original: Subtle ): void => {
      sabotaged.encrypt = ( ...args: Parameters<Subtle[ 'encrypt' ]> ): Promise<ArrayBuffer> => original.encrypt( ...args );
    } );
    try {
      t.truthy( Object.getOwnPropertyDescriptor( crypto, 'subtle' ) );
    } finally {
      override.restore();
    }
    t.deepEqual( Object.getOwnPropertyDescriptor( crypto, 'subtle' ), installedDescriptor );
  } finally {
    if( fixtureDescriptor ) {
      Object.defineProperty( crypto, 'subtle', fixtureDescriptor );
    } else {
      delete ( crypto as unknown as Record<PropertyKey, unknown> )[ 'subtle' ];
    }
  }
  t.deepEqual( Object.getOwnPropertyDescriptor( crypto, 'subtle' ), absentDescriptor );
} );

test( 'the options types reject removed and invalid fields at compile time', async ( t: ExecutionContext ) => {
  const obsoleteOptions: SessionsManagerOptions = {
    // @ts-expect-error algo is removed; sessions always use fixed AES-GCM.
    algo: { name: 'AES-GCM', length: 256, tagLength: 128 },
    encryptionKey: key32
  };
  const removedExpires: SessionsManagerOptions = {
    cookie: {
      // @ts-expect-error expires is removed; the cookie lifetime derives from validityToken.
      expires: new Date()
    }
  };
  const removedHttpOnly: SessionsManagerOptions = {
    cookie: {
      // @ts-expect-error httpOnly is removed; the cookie is always HttpOnly.
      httpOnly: false
    }
  };
  const removedMaxAge: SessionsManagerOptions = {
    cookie: {
      // @ts-expect-error maxAge is removed; Max-Age derives from validityToken.
      maxAge: 3600
    }
  };
  const removedPartitioned: SessionsManagerOptions = {
    cookie: {
      // @ts-expect-error partitioned is removed; use mode 'partitioned'.
      partitioned: true
    }
  };
  const removedPriority: SessionsManagerOptions = {
    cookie: {
      // @ts-expect-error priority is removed.
      priority: 'High'
    }
  };
  const removedSameSite: SessionsManagerOptions = {
    cookie: {
      // @ts-expect-error sameSite is removed; use mode.
      sameSite: 'Strict'
    }
  };
  const invalidMode: NonNullable<SessionsManagerOptions[ 'cookie' ]> = {
    // @ts-expect-error 'none' is not a valid cookie mode.
    mode: 'none'
  };
  const validMode: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'mode' ]> = 'partitioned';
  const validName: NonNullable<NonNullable<SessionsManagerOptions[ 'cookie' ]>[ 'name' ]> = 'custom';
  const manager: SessionsManager = await SessionsManager.create( obsoleteOptions );
  t.truthy( manager );
  t.truthy( removedExpires );
  t.truthy( removedHttpOnly );
  t.truthy( removedMaxAge );
  t.truthy( removedPartitioned );
  t.truthy( removedPriority );
  t.truthy( removedSameSite );
  t.truthy( invalidMode );
  t.is( validMode, 'partitioned' );
  t.is( validName, 'custom' );
} );

test( 'the package exports the SessionsManager class and no longer exports the free factory', ( t: ExecutionContext ): void => {
  t.false( 'createSessionsManager' in packageModule );
  t.true( 'function' === typeof packageModule.SessionsManager );
  t.is( packageModule.SessionsManager.name, 'SessionsManager' );
} );

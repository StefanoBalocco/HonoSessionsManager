import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import type { ExecutionContext } from 'ava';
import type { Context } from 'hono';
import type { JSONValue, Session, SessionsEnv, SessionsManager, Undefinedable } from '../../dist/index.js';

export function createTestApp( manager: SessionsManager, cookieName: string = 'session' ): Hono<SessionsEnv> {
  const app: Hono<SessionsEnv> = new Hono<SessionsEnv>();
  app.use( '*', manager.middleware );
  app.post( '/create', async ( context: Context<SessionsEnv> ): Promise<Response> => {
    await manager.create( context );
    return context.json( { created: true } );
  } );
  app.get( '/verify', ( context: Context<SessionsEnv> ): Response => {
    const session: Undefinedable<Session> = context.get( 'session' );
    return context.json( { authenticated: undefined !== session } );
  } );
  app.post( '/set/:key', async ( context: Context<SessionsEnv> ): Promise<Response> => {
    const session: Undefinedable<Session> = context.get( 'session' );
    let returnValue: Response;
    if( session ) {
      const key: string = context.req.param( 'key' ) ?? '';
      const value: JSONValue = await context.req.json<JSONValue>();
      const stored: boolean = await session.data.set( key, value );
      returnValue = context.json( { stored } );
    } else {
      returnValue = context.json( { stored: false }, 401 );
    }
    return returnValue;
  } );
  app.get( '/get/:key', async ( context: Context<SessionsEnv> ): Promise<Response> => {
    const session: Undefinedable<Session> = context.get( 'session' );
    let returnValue: Response;
    if( session ) {
      const key: string = context.req.param( 'key' ) ?? '';
      const value: Undefinedable<JSONValue> = await session.data.get( key );
      returnValue = context.json( { value: undefined === value ? null : value } );
    } else {
      returnValue = context.json( { value: null }, 401 );
    }
    return returnValue;
  } );
  app.post( '/logout', async ( context: Context<SessionsEnv> ): Promise<Response> => {
    const token: Undefinedable<string> = getCookie( context, cookieName );
    const deleted: boolean = await manager.delete( context, token ?? '' );
    const cleared: boolean = undefined === context.get( 'session' );
    return context.json( { cleared, deleted } );
  } );
  return app;
}

export function cookiePairFrom( setCookieValue: string ): string {
  const returnValue: string = setCookieValue.split( ';' )[ 0 ];
  return returnValue;
}

export function tokenFromSetCookie( setCookieValue: string ): string {
  const pair: string = cookiePairFrom( setCookieValue );
  const separatorIndex: number = pair.indexOf( '=' );
  const returnValue: string = pair.slice( separatorIndex + 1 );
  return returnValue;
}

export function assertNoSetCookie( t: ExecutionContext, response: Response ): void {
  t.is( response.headers.get( 'set-cookie' ), null );
}

export function jsonResponse<T>( response: Response ): Promise<T> {
  const returnValue: Promise<T> = response.json() as Promise<T>;
  return returnValue;
}

export {
  Base64UrlDecode as base64UrlDecode,
  Base64UrlEncode as base64UrlEncode
} from '../../dist/Utilities.js';
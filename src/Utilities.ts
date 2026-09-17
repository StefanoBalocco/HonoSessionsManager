export function TimingSafeEqual( left: Uint8Array<ArrayBuffer>, right: Uint8Array<ArrayBuffer> ): boolean {
  let returnValue: boolean = false;
  if( left.length === right.length ) {
    let difference: number = 0;

    for( let iL1: number = 0; iL1 < left.length; iL1++ ) {
      difference |= left[ iL1 ] ^ right[ iL1 ];
    }

    returnValue = !difference;
  }
  return returnValue;
}

export function Base64UrlEncode( bytes: Uint8Array<ArrayBuffer> ): string {
  let standardText: string = '';
  for( const byte of bytes ) {
    standardText += String.fromCharCode( byte );
  }
  return btoa( standardText ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
}

const base64urlPattern: RegExp = /^[A-Za-z0-9_-]*$/;
export function Base64UrlDecode( text: string ): Uint8Array<ArrayBuffer> {
  if( base64urlPattern.test( text ) && ( 1 !== ( text.length % 4 ) ) ) {
    const paddingLength: number = ( 4 - ( text.length % 4 ) ) % 4;
    const standardText: string = atob( text.replace( /-/g, '+' ).replace( /_/g, '/' ) + '='.repeat( paddingLength ) );
    const returnValue: Uint8Array<ArrayBuffer> = new Uint8Array( standardText.length );
    for( let iL1: number = 0; iL1 < standardText.length; iL1++ ) {
      returnValue[ iL1 ] = standardText.charCodeAt( iL1 );
    }
    return returnValue;
  } else {
    throw new Error( 'Malformed base64url token' );
  }
}

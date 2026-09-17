export function TimingSafeEqual(left, right) {
    let returnValue = false;
    if (left.length === right.length) {
        let difference = 0;
        for (let iL1 = 0; iL1 < left.length; iL1++) {
            difference |= left[iL1] ^ right[iL1];
        }
        returnValue = !difference;
    }
    return returnValue;
}
export function Base64UrlEncode(bytes) {
    let standardText = '';
    for (const byte of bytes) {
        standardText += String.fromCharCode(byte);
    }
    return btoa(standardText).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const base64urlPattern = /^[A-Za-z0-9_-]*$/;
export function Base64UrlDecode(text) {
    if (base64urlPattern.test(text) && (1 !== (text.length % 4))) {
        const paddingLength = (4 - (text.length % 4)) % 4;
        const standardText = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(paddingLength));
        const returnValue = new Uint8Array(standardText.length);
        for (let iL1 = 0; iL1 < standardText.length; iL1++) {
            returnValue[iL1] = standardText.charCodeAt(iL1);
        }
        return returnValue;
    }
    else {
        throw new Error('Malformed base64url token');
    }
}

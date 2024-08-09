"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getTlsVersionFromBytes = exports.chunkUint8Array = exports.isSymmetricCipher = exports.unpadTls = exports.padTls = exports.generateIV = exports.uint8ArrayToStr = exports.strToUint8Array = exports.uint8ArrayToDataView = exports.areUint8ArraysEqual = exports.concatenateUint8Arrays = exports.xor = exports.toHexStringWithWhitespace = void 0;
const constants_1 = require("./constants");
/**
 * Converts a buffer to a hex string with whitespace between each byte
 * @returns eg. '01 02 03 04'
 */
function toHexStringWithWhitespace(buff, whitespace = ' ') {
    return [...buff]
        .map(x => x.toString(16).padStart(2, '0'))
        .join(whitespace);
}
exports.toHexStringWithWhitespace = toHexStringWithWhitespace;
function xor(a, b) {
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
exports.xor = xor;
function concatenateUint8Arrays(arrays) {
    const totalLength = arrays.reduce((acc, curr) => acc + curr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
exports.concatenateUint8Arrays = concatenateUint8Arrays;
function areUint8ArraysEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}
exports.areUint8ArraysEqual = areUint8ArraysEqual;
function uint8ArrayToDataView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
exports.uint8ArrayToDataView = uint8ArrayToDataView;
function strToUint8Array(str) {
    return new TextEncoder().encode(str);
}
exports.strToUint8Array = strToUint8Array;
function uint8ArrayToStr(arr) {
    return new TextDecoder().decode(arr);
}
exports.uint8ArrayToStr = uint8ArrayToStr;
function generateIV(iv, recordNumber) {
    // make the recordNumber a buffer, so we can XOR with the main IV
    // to generate the specific IV to decrypt this packet
    const recordBuffer = new Uint8Array(iv.length);
    const recordBufferView = new DataView(recordBuffer.buffer);
    recordBufferView.setUint32(iv.length - 4, recordNumber);
    return xor(iv, recordBuffer);
}
exports.generateIV = generateIV;
/**
 * TLS has this special sort of padding where the last byte
 * is the number of padding bytes, and all the padding bytes
 * are the same as the last byte.
 * Eg. for an 8 byte block [ 0x0a, 0x0b, 0x0c, 0xd ]
 * -> [ 0x0a, 0x0b, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x04 ]
 */
function padTls(data, blockSize) {
    const nextMultiple = data.length % blockSize === 0
        ? data.length + blockSize
        : Math.ceil(data.length / blockSize) * blockSize;
    const paddingLength = nextMultiple - data.length;
    const paddingNum = paddingLength - 1;
    const padded = new Uint8Array(nextMultiple);
    padded.set(data);
    padded.fill(paddingNum, data.length);
    padded.fill(paddingNum, nextMultiple - 1);
    return padded;
}
exports.padTls = padTls;
/**
 * Unpad a TLS-spec padded buffer
 */
function unpadTls(data) {
    const paddingLength = data[data.length - 1];
    for (let i = 0; i < paddingLength; i++) {
        if (data[data.length - 1 - i] !== paddingLength) {
            throw new Error('Invalid padding');
        }
    }
    return data.slice(0, data.length - paddingLength);
}
exports.unpadTls = unpadTls;
function isSymmetricCipher(cipher) {
    return cipher === 'AES-128-CBC';
}
exports.isSymmetricCipher = isSymmetricCipher;
function chunkUint8Array(arr, chunkSize) {
    const result = [];
    for (let i = 0; i < arr.length; i += chunkSize) {
        result.push(arr.slice(i, i + chunkSize));
    }
    return result;
}
exports.chunkUint8Array = chunkUint8Array;
function getTlsVersionFromBytes(bytes) {
    const supportedV = Object.entries(constants_1.TLS_PROTOCOL_VERSION_MAP)
        .find(([, v]) => areUint8ArraysEqual(v, bytes));
    if (!supportedV) {
        throw new Error(`Unsupported TLS version '${bytes}'`);
    }
    return supportedV[0];
}
exports.getTlsVersionFromBytes = getTlsVersionFromBytes;

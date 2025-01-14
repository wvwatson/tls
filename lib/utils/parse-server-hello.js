"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseServerHello = void 0;
const crypto_1 = require("../crypto");
const constants_1 = require("./constants");
const generics_1 = require("./generics");
const packets_1 = require("./packets");
const parse_extensions_1 = require("./parse-extensions");
async function parseServerHello(data) {
    // header TLS version (expected to be 0x0303)
    read(2);
    const serverRandom = read(32);
    const sessionId = readWLength(1);
    const cipherSuiteBytes = read(2);
    const cipherSuite = constants_1.SUPPORTED_CIPHER_SUITES
        .find(k => (0, generics_1.areUint8ArraysEqual)(constants_1.SUPPORTED_CIPHER_SUITE_MAP[k].identifier, cipherSuiteBytes));
    if (!cipherSuite) {
        throw new Error(`Unsupported cipher suite '${cipherSuiteBytes}'`);
    }
    const compressionMethod = read(1)[0];
    if (compressionMethod !== 0x00) {
        throw new Error(`Unsupported compression method '${compressionMethod.toString(16)}'`);
    }
    const extensions = (0, parse_extensions_1.parseServerExtensions)(data);
    const serverTlsVersion = extensions['SUPPORTED_VERSIONS'] || 'TLS1_2';
    const pubKeyExt = extensions['KEY_SHARE'];
    if (serverTlsVersion === 'TLS1_3'
        && !pubKeyExt) {
        throw new Error('Missing key share in TLS 1.3');
    }
    return {
        serverTlsVersion,
        serverRandom,
        sessionId,
        cipherSuite,
        supportsPsk: !!extensions['PRE_SHARED_KEY']?.supported,
        extensions,
        ...(pubKeyExt
            ? {
                publicKey: await crypto_1.crypto.importKey(constants_1.SUPPORTED_NAMED_CURVE_MAP[pubKeyExt.type].algorithm, pubKeyExt.publicKey, 'public'),
                publicKeyType: pubKeyExt.type,
            }
            : {})
    };
    function read(bytes) {
        const result = data.slice(0, bytes);
        data = data.slice(bytes);
        return result;
    }
    function readWLength(bytesLength = 2) {
        const content = (0, packets_1.expectReadWithLength)(data, bytesLength);
        data = data.slice(content.length + bytesLength);
        return content;
    }
}
exports.parseServerHello = parseServerHello;

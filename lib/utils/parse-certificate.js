"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyCertificateChain = exports.getSignatureDataTls12 = exports.getSignatureDataTls13 = exports.verifyCertificateSignature = exports.parseServerCertificateVerify = exports.parseCertificates = void 0;
const crypto_1 = require("../crypto");
const constants_1 = require("./constants");
const decryption_utils_1 = require("./decryption-utils");
const generics_1 = require("./generics");
const packets_1 = require("./packets");
const root_ca_1 = require("./root-ca");
const x509_1 = require("./x509");
const CERT_VERIFY_TXT = (0, generics_1.strToUint8Array)('TLS 1.3, server CertificateVerify');
function parseCertificates(data, { version }) {
    // context, kina irrelevant
    const ctx = version === 'TLS1_3' ? read(1)[0] : 0;
    // the data itself
    data = readWLength(3);
    const certificates = [];
    while (data.length) {
        // the certificate data
        const cert = readWLength(3);
        const certObj = (0, x509_1.loadX509FromDer)(cert);
        certificates.push(certObj);
        if (version === 'TLS1_3') {
            // extensions
            readWLength(2);
        }
    }
    return { certificates, ctx };
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
exports.parseCertificates = parseCertificates;
function parseServerCertificateVerify(data) {
    // data = readWLength(2)
    const algorithmBytes = read(2);
    const algorithm = constants_1.SUPPORTED_SIGNATURE_ALGS.find(alg => ((0, generics_1.areUint8ArraysEqual)(constants_1.SUPPORTED_SIGNATURE_ALGS_MAP[alg]
        .identifier, algorithmBytes)));
    if (!algorithm) {
        throw new Error(`Unsupported signature algorithm '${algorithmBytes}'`);
    }
    const signature = readWLength(2);
    return { algorithm, signature };
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
exports.parseServerCertificateVerify = parseServerCertificateVerify;
async function verifyCertificateSignature({ signature, algorithm, publicKey, signatureData, }) {
    const { algorithm: cryptoAlg } = constants_1.SUPPORTED_SIGNATURE_ALGS_MAP[algorithm];
    const pubKey = await crypto_1.crypto.importKey(cryptoAlg, publicKey, 'public');
    const verified = await crypto_1.crypto.verify(cryptoAlg, {
        data: signatureData,
        signature,
        publicKey: pubKey
    });
    if (!verified) {
        throw new Error(`${algorithm} signature verification failed`);
    }
}
exports.verifyCertificateSignature = verifyCertificateSignature;
async function getSignatureDataTls13(hellos, cipherSuite) {
    const handshakeHash = await (0, decryption_utils_1.getHash)(hellos, cipherSuite);
    return (0, generics_1.concatenateUint8Arrays)([
        new Uint8Array(64).fill(0x20),
        CERT_VERIFY_TXT,
        new Uint8Array([0]),
        handshakeHash
    ]);
}
exports.getSignatureDataTls13 = getSignatureDataTls13;
async function getSignatureDataTls12({ clientRandom, serverRandom, curveType, publicKey, }) {
    const publicKeyBytes = await crypto_1.crypto.exportKey(publicKey);
    return (0, generics_1.concatenateUint8Arrays)([
        clientRandom,
        serverRandom,
        (0, generics_1.concatenateUint8Arrays)([
            new Uint8Array([3]),
            constants_1.SUPPORTED_NAMED_CURVE_MAP[curveType].identifier,
        ]),
        (0, packets_1.packWithLength)(publicKeyBytes)
            // pub key is packed with 1 byte length
            .slice(1)
    ]);
}
exports.getSignatureDataTls12 = getSignatureDataTls12;
async function verifyCertificateChain(chain, host, additionalRootCAs) {
    const rootCAs = [
        ...root_ca_1.ROOT_CAS,
        ...additionalRootCAs || []
    ];
    const commonNames = [
        ...chain[0].getSubjectField('CN'),
        ...chain[0].getAlternativeDNSNames()
    ];
    if (!commonNames.some(cn => matchHostname(host, cn))) {
        throw new Error(`Certificate is not for host ${host}`);
    }
    let tmpChain = [...chain];
    let rootCert = tmpChain.shift();
    // look for issuers until we hit the end
    while (tmpChain.length) {
        const cn = rootCert.getSubjectField('CN');
        const issuer = findIssuer(tmpChain, rootCert);
        //in case there are orphan certificates in chain, but we found the root
        if (!issuer) {
            break;
        }
        if (!rootCert.isWithinValidity()) {
            throw new Error(`Certificate ${cn} is not within validity period`);
        }
        if (!issuer.cert.isIssuer(rootCert)) {
            throw new Error(`Certificate ${cn} was not issued by certificate ${issuer.cert.getSubjectField('CN')}`);
        }
        if (!(await issuer.cert.verifyIssued(rootCert))) {
            throw new Error(`Certificate ${cn} issue verification failed`);
        }
        //remove issuer cert from chain
        tmpChain.splice(issuer.index, 1);
        rootCert = issuer.cert;
    }
    const rootIssuer = rootCAs.find(r => r.isIssuer(rootCert));
    if (!rootIssuer) {
        throw new Error('Root CA not found. Could not verify certificate');
    }
    const verified = await rootIssuer.verifyIssued(rootCert);
    if (!verified) {
        throw new Error('Root CA did not issue certificate');
    }
    function findIssuer(chain, cert) {
        for (let i = 0; i < chain.length; i++) {
            if (chain[i].isIssuer(cert)) {
                return { cert: chain[i], index: i };
            }
        }
        return null;
    }
}
exports.verifyCertificateChain = verifyCertificateChain;
/**
 * Checks if a hostname matches a common name
 * @param host the hostname, eg. "google.com"
 * @param commonName the common name from the certificate,
 * 	eg. "*.google.com", "google.com"
 */
function matchHostname(host, commonName) {
    // write a regex to match the common name
    // and check if it matches the hostname
    const hostComps = host.split('.');
    const cnComps = commonName.split('.');
    if (cnComps.length !== hostComps.length) {
        // can ignore the first component if it's a wildcard
        if (cnComps[0] === '*'
            && cnComps.length === hostComps.length + 1) {
            cnComps.shift();
        }
        else {
            return false;
        }
    }
    return hostComps.every((comp, i) => (comp === cnComps[i]
        || cnComps[i] === '*'));
}

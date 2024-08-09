"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeTLSClient = void 0;
const client_hello_1 = require("./utils/client-hello");
const constants_1 = require("./utils/constants");
const decryption_utils_1 = require("./utils/decryption-utils");
const finish_messages_1 = require("./utils/finish-messages");
const generics_1 = require("./utils/generics");
const key_share_1 = require("./utils/key-share");
const key_update_1 = require("./utils/key-update");
const logger_1 = require("./utils/logger");
const make_queue_1 = require("./utils/make-queue");
const packets_1 = require("./utils/packets");
const parse_alert_1 = require("./utils/parse-alert");
const parse_certificate_1 = require("./utils/parse-certificate");
const parse_extensions_1 = require("./utils/parse-extensions");
const parse_server_hello_1 = require("./utils/parse-server-hello");
const session_ticket_1 = require("./utils/session-ticket");
const wrapped_record_1 = require("./utils/wrapped-record");
const crypto_1 = require("./crypto");
const RECORD_LENGTH_BYTES = 3;
function makeTLSClient({ host, verifyServerCertificate, rootCAs, logger: _logger, cipherSuites, namedCurves, supportedProtocolVersions, signatureAlgorithms, applicationLayerProtocols, write, onRead, onApplicationData, onSessionTicket, onTlsEnd, onHandshake, onRecvCertificates }) {
    verifyServerCertificate = verifyServerCertificate !== false;
    namedCurves = namedCurves || constants_1.SUPPORTED_NAMED_CURVES;
    const logger = _logger || logger_1.logger;
    const processor = (0, packets_1.makeMessageProcessor)(logger);
    const { enqueue: enqueueServerPacket } = (0, make_queue_1.makeQueue)();
    const keyPairs = {};
    let handshakeDone = false;
    let ended = false;
    let sessionId = new Uint8Array();
    let handshakeMsgs = [];
    let cipherSuite = undefined;
    let earlySecret = undefined;
    let keys = undefined;
    let recordSendCount = 0;
    let recordRecvCount = 0;
    let keyType = undefined;
    let connTlsVersion = undefined;
    let clientRandom = undefined;
    let serverRandom = undefined;
    let cipherSpecChanged = false;
    let selectedAlpn;
    let certificates;
    let handshakePacketStream = new Uint8Array();
    let clientCertificateRequested = false;
    let certificatesVerified = false;
    const processPacketUnsafe = async (type, { header, content }) => {
        if (ended) {
            logger.warn('connection closed, ignoring packet');
            return;
        }
        let contentType;
        let ctx = { type: 'plaintext' };
        // if the cipher spec has changed,
        // the data will be encrypted, so
        // we need to decrypt the packet
        if (cipherSpecChanged || type === constants_1.PACKET_TYPE.WRAPPED_RECORD) {
            logger.trace('recv wrapped record');
            const macKey = 'serverMacKey' in keys
                ? keys.serverMacKey
                : undefined;
            const decrypted = await (0, wrapped_record_1.decryptWrappedRecord)(content, {
                key: keys.serverEncKey,
                iv: keys.serverIv,
                recordHeader: header,
                recordNumber: recordRecvCount,
                cipherSuite: cipherSuite,
                version: connTlsVersion,
                macKey,
            });
            if (connTlsVersion === 'TLS1_3') {
                // TLS 1.3 has an extra byte suffixed
                // this denotes the content type of the
                // packet
                const contentTypeNum = decrypted
                    .plaintext[decrypted.plaintext.length - 1];
                contentType = Object.entries(constants_1.CONTENT_TYPE_MAP)
                    .find(([, val]) => val === contentTypeNum)?.[0];
            }
            ctx = {
                type: 'ciphertext',
                encKey: keys.serverEncKey,
                fixedIv: keys.serverIv,
                iv: decrypted.iv,
                recordNumber: recordRecvCount,
                macKey,
                ciphertext: content,
                plaintext: decrypted.plaintext,
                contentType,
            };
            content = decrypted.plaintext;
            if (contentType) {
                content = content.slice(0, -1);
            }
            logger.trace({
                recordRecvCount,
                contentType,
                length: content.length,
            }, 'decrypted wrapped record');
            recordRecvCount += 1;
        }
        onRead?.({ content, header }, ctx);
        if (type === constants_1.PACKET_TYPE.WRAPPED_RECORD
            || type === constants_1.PACKET_TYPE.HELLO) {
            // do nothing -- pass through
        }
        else if (type === constants_1.PACKET_TYPE.CHANGE_CIPHER_SPEC) {
            logger.debug('received change cipher spec');
            cipherSpecChanged = true;
            return;
        }
        else if (type === constants_1.PACKET_TYPE.ALERT) {
            await handleAlert(content);
            return;
        }
        else {
            logger.warn({
                type: type.toString(16),
                chunk: (0, generics_1.toHexStringWithWhitespace)(content)
            }, 'cannot process message');
            return;
        }
        try {
            await processRecord({
                content,
                contentType: contentType
                    ? constants_1.CONTENT_TYPE_MAP[contentType]
                    : undefined,
                header,
            });
        }
        catch (err) {
            logger.error({ err }, 'error processing record');
            end(err);
        }
    };
    const processPacket = (...args) => (enqueueServerPacket(processPacketUnsafe, ...args));
    async function processRecord({ content: record, contentType, header, }) {
        contentType ??= header[0];
        if (contentType === constants_1.CONTENT_TYPE_MAP.HANDSHAKE) {
            handshakePacketStream = (0, generics_1.concatenateUint8Arrays)([handshakePacketStream, record]);
            let data;
            while (data = readPacket()) {
                const { type, content } = data;
                switch (type) {
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.SERVER_HELLO:
                        logger.trace('received server hello');
                        const hello = await (0, parse_server_hello_1.parseServerHello)(content);
                        if (!hello.supportsPsk && earlySecret) {
                            throw new Error('Server does not support PSK');
                        }
                        cipherSuite = hello.cipherSuite;
                        connTlsVersion = hello.serverTlsVersion;
                        serverRandom = hello.serverRandom;
                        setAlpn(hello.extensions?.ALPN);
                        logger.debug({
                            cipherSuite,
                            connTlsVersion,
                            selectedAlpn,
                        }, 'processed server hello');
                        if (hello.publicKeyType && hello.publicKey) {
                            await processServerPubKey({
                                publicKeyType: hello.publicKeyType,
                                publicKey: hello.publicKey
                            });
                        }
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.ENCRYPTED_EXTENSIONS:
                        const extData = (0, parse_extensions_1.parseServerExtensions)(content);
                        logger.debug({
                            len: content.length,
                            extData
                        }, 'received encrypted extensions');
                        setAlpn(extData?.ALPN);
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.HELLO_RETRY_REQUEST:
                        throw new Error('Hello retry not supported. Please re-establish connection');
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE:
                        logger.trace({ len: content.length }, 'received certificate');
                        const result = (0, parse_certificate_1.parseCertificates)(content, { version: connTlsVersion });
                        certificates = result.certificates;
                        logger.debug({ len: certificates.length }, 'parsed certificates');
                        onRecvCertificates?.({ certificates });
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE_VERIFY:
                        logger.debug({ len: content.length }, 'received certificate verify');
                        const signature = (0, parse_certificate_1.parseServerCertificateVerify)(content);
                        logger.debug({ alg: signature.algorithm }, 'parsed certificate verify');
                        if (!certificates?.length) {
                            throw new Error('No certificates received');
                        }
                        const signatureData = await (0, parse_certificate_1.getSignatureDataTls13)(handshakeMsgs.slice(0, -1), cipherSuite);
                        await (0, parse_certificate_1.verifyCertificateSignature)({
                            ...signature,
                            publicKey: certificates[0].getPublicKey(),
                            signatureData,
                        });
                        if (verifyServerCertificate) {
                            await (0, parse_certificate_1.verifyCertificateChain)(certificates, host, rootCAs);
                            logger.debug('verified certificate chain');
                            certificatesVerified = true;
                        }
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.FINISHED:
                        await processServerFinish(content);
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.KEY_UPDATE:
                        const newMasterSecret = await (0, decryption_utils_1.computeUpdatedTrafficMasterSecret)(keys.serverSecret, cipherSuite);
                        const newKeys = await (0, decryption_utils_1.deriveTrafficKeysForSide)(newMasterSecret, cipherSuite);
                        keys = {
                            ...keys,
                            serverSecret: newMasterSecret,
                            serverEncKey: newKeys.encKey,
                            serverIv: newKeys.iv,
                        };
                        recordRecvCount = 0;
                        logger.debug('updated server traffic keys');
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.SESSION_TICKET:
                        if (connTlsVersion === 'TLS1_3') {
                            logger.debug({ len: record.length }, 'received session ticket');
                            const ticket = (0, session_ticket_1.parseSessionTicket)(content);
                            onSessionTicket?.(ticket);
                        }
                        else {
                            logger.warn('ignoring received session ticket in TLS 1.2');
                        }
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE_REQUEST:
                        logger.debug('received client certificate request');
                        clientCertificateRequested = true;
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.SERVER_KEY_SHARE:
                        logger.trace('received server key share');
                        if (!certificates?.length) {
                            throw new Error('No certificates received');
                        }
                        // extract pub key & signature of pub key with cert
                        const keyShare = await (0, key_share_1.processServerKeyShare)(content);
                        // compute signature data
                        const signatureData12 = await (0, parse_certificate_1.getSignatureDataTls12)({
                            clientRandom: clientRandom,
                            serverRandom: serverRandom,
                            curveType: keyShare.publicKeyType,
                            publicKey: keyShare.publicKey,
                        });
                        // verify signature
                        await (0, parse_certificate_1.verifyCertificateSignature)({
                            signature: keyShare.signatureBytes,
                            algorithm: keyShare.signatureAlgorithm,
                            publicKey: certificates[0].getPublicKey(),
                            signatureData: signatureData12,
                        });
                        logger.debug('verified server key share signature');
                        if (verifyServerCertificate) {
                            await (0, parse_certificate_1.verifyCertificateChain)(certificates, host, rootCAs);
                            logger.debug('verified certificate chain');
                            certificatesVerified = true;
                        }
                        // compute shared keys
                        await processServerPubKey(keyShare);
                        break;
                    case constants_1.SUPPORTED_RECORD_TYPE_MAP.SERVER_HELLO_DONE:
                        logger.debug('server hello done');
                        if (!keyType) {
                            throw new Error('Key exchange without key-share not supported');
                        }
                        const clientPubKey = keyPairs[keyType].pubKey;
                        const clientKeyShare = await (0, key_share_1.packClientKeyShare)(clientPubKey);
                        await writePacket({
                            type: 'HELLO',
                            data: clientKeyShare
                        });
                        handshakeMsgs.push(clientKeyShare);
                        await writeChangeCipherSpec();
                        const finishMsg = await (0, finish_messages_1.packClientFinishTls12)({
                            secret: keys.masterSecret,
                            handshakeMessages: handshakeMsgs,
                            cipherSuite: cipherSuite,
                        });
                        await writeEncryptedPacket({
                            data: finishMsg,
                            type: 'HELLO',
                        });
                        handshakeMsgs.push(finishMsg);
                        break;
                    default:
                        logger.warn({ type: type.toString(16) }, 'cannot process record');
                        break;
                }
            }
            function readPacket() {
                if (!handshakePacketStream.length) {
                    return;
                }
                const type = handshakePacketStream[0];
                const content = (0, packets_1.readWithLength)(handshakePacketStream.slice(1), RECORD_LENGTH_BYTES);
                if (!content) {
                    logger.warn('missing bytes from packet');
                    return;
                }
                const totalLength = 1 + RECORD_LENGTH_BYTES + content.length;
                if (!handshakeDone) {
                    handshakeMsgs.push(handshakePacketStream.slice(0, totalLength));
                }
                handshakePacketStream = handshakePacketStream.slice(totalLength);
                return { type, content };
            }
        }
        else if (contentType === constants_1.CONTENT_TYPE_MAP.APPLICATION_DATA) {
            logger.trace({ len: record.length }, 'received application data');
            onApplicationData?.(record);
        }
        else if (contentType === constants_1.CONTENT_TYPE_MAP.ALERT) {
            await handleAlert(record);
        }
        else {
            logger.warn({ record: record, contentType: contentType?.toString(16) }, 'cannot process record');
        }
    }
    function setAlpn(alpn) {
        selectedAlpn = alpn || applicationLayerProtocols?.[0];
        if (selectedAlpn && !applicationLayerProtocols?.includes(selectedAlpn)) {
            throw new Error(`Server selected unsupported ALPN: "${selectedAlpn}"`);
        }
    }
    async function handleAlert(content) {
        if (ended) {
            logger.warn('connection closed, ignoring alert');
            return;
        }
        const { level, description } = (0, parse_alert_1.parseTlsAlert)(content);
        const msg = (description === 'HANDSHAKE_FAILURE' || description === 'PROTOCOL_VERSION'
            ? 'Unsupported TLS version'
            : 'received alert');
        logger[level === 'WARNING' ? 'warn' : 'error']({ level, description }, msg);
        if (level === 'FATAL'
            || description === 'CLOSE_NOTIFY') {
            end(level === 'FATAL'
                ? new Error(`Fatal alert: ${description}`)
                : undefined);
        }
    }
    async function sendClientCertificate() {
        if (clientCertificateRequested) {
            const clientZeroCert = (0, generics_1.concatenateUint8Arrays)([
                new Uint8Array([constants_1.SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE, 0x00]),
                (0, packets_1.packWithLength)(new Uint8Array([0, 0, 0, 0]))
            ]);
            logger.trace({ cert: (0, generics_1.toHexStringWithWhitespace)(clientZeroCert) }, 'sending zero certs');
            await writeEncryptedPacket({
                type: 'WRAPPED_RECORD',
                data: clientZeroCert,
                contentType: 'HANDSHAKE'
            });
            handshakeMsgs.push(clientZeroCert);
        }
    }
    async function processServerFinish(serverFinish) {
        logger.debug('received server finish');
        if (!certificatesVerified && verifyServerCertificate) {
            throw new Error('Finish received before certificate verification');
        }
        if (connTlsVersion === 'TLS1_2') {
            await processServerFinishTls12(serverFinish);
        }
        else {
            await processServerFinishTls13(serverFinish);
        }
        handshakeDone = true;
        onHandshake?.();
    }
    async function processServerFinishTls12(serverFinish) {
        const genServerFinish = await (0, finish_messages_1.generateFinishTls12)('server', {
            handshakeMessages: handshakeMsgs.slice(0, -1),
            secret: keys.masterSecret,
            cipherSuite: cipherSuite,
        });
        if (!(0, generics_1.areUint8ArraysEqual)(genServerFinish, serverFinish)) {
            throw new Error('Server finish does not match');
        }
    }
    async function processServerFinishTls13(serverFinish) {
        // derive server keys now to streamline handshake messages handling
        const serverKeys = await (0, decryption_utils_1.computeSharedKeys)({
            // we only use handshake messages till the server finish
            hellos: handshakeMsgs,
            cipherSuite: cipherSuite,
            secretType: 'ap',
            masterSecret: keys.masterSecret,
        });
        // the server hash computation does not include
        // the server finish, so we need to exclude it
        const handshakeMsgsForServerHash = handshakeMsgs.slice(0, -1);
        await (0, finish_messages_1.verifyFinishMessage)(serverFinish, {
            secret: keys.serverSecret,
            handshakeMessages: handshakeMsgsForServerHash,
            cipherSuite: cipherSuite
        });
        logger.debug('server finish verified');
        // this might add an extra message to handshakeMsgs and affect handshakeHash
        await sendClientCertificate();
        const clientFinish = await (0, finish_messages_1.packFinishMessagePacket)({
            secret: keys.clientSecret,
            handshakeMessages: handshakeMsgs,
            cipherSuite: cipherSuite
        });
        logger.trace({ finish: (0, generics_1.toHexStringWithWhitespace)(clientFinish) }, 'sending client finish');
        await writeEncryptedPacket({
            type: 'WRAPPED_RECORD',
            data: clientFinish,
            contentType: 'HANDSHAKE'
        });
        // add the client finish to the handshake messages
        handshakeMsgs.push(clientFinish);
        // switch to using the provider keys
        keys = serverKeys;
        // also the send/recv counters are reset
        // once we switch to the provider keys
        recordSendCount = 0;
        recordRecvCount = 0;
    }
    async function processServerPubKey(data) {
        keyType = data.publicKeyType;
        const { keyPair, algorithm } = await getKeyPair(data.publicKeyType);
        const sharedSecret = await crypto_1.crypto.calculateSharedSecret(algorithm, keyPair.privKey, data.publicKey);
        if (connTlsVersion === 'TLS1_2') {
            keys = await (0, decryption_utils_1.computeSharedKeysTls12)({
                preMasterSecret: sharedSecret,
                clientRandom: clientRandom,
                serverRandom: serverRandom,
                cipherSuite: cipherSuite,
            });
        }
        else {
            keys = await (0, decryption_utils_1.computeSharedKeys)({
                hellos: handshakeMsgs,
                cipherSuite: cipherSuite,
                secretType: 'hs',
                masterSecret: sharedSecret,
                earlySecret,
            });
        }
        logger.debug({ keyType }, 'computed shared keys');
    }
    async function writeChangeCipherSpec() {
        logger.debug('sending change cipher spec');
        const changeCipherSpecData = new Uint8Array([1]);
        await writePacket({
            type: 'CHANGE_CIPHER_SPEC',
            data: changeCipherSpecData
        });
    }
    async function writeEncryptedPacket(opts) {
        logger.trace({ ...opts, data: (0, generics_1.toHexStringWithWhitespace)(opts.data) }, 'writing enc packet');
        const macKey = 'clientMacKey' in keys
            ? keys.clientMacKey
            : undefined;
        let plaintext = opts.data;
        if (connTlsVersion === 'TLS1_3'
            && typeof opts.contentType !== 'undefined') {
            plaintext = (0, generics_1.concatenateUint8Arrays)([
                plaintext,
                new Uint8Array([constants_1.CONTENT_TYPE_MAP[opts.contentType]])
            ]);
        }
        const { ciphertext, iv } = await (0, wrapped_record_1.encryptWrappedRecord)(plaintext, {
            key: keys.clientEncKey,
            iv: keys.clientIv,
            recordNumber: recordSendCount,
            cipherSuite: cipherSuite,
            macKey,
            recordHeaderOpts: {
                type: opts.type,
                version: opts.version
            },
            version: connTlsVersion,
        });
        const header = (0, packets_1.packPacketHeader)(ciphertext.length, opts);
        await write({ header, content: ciphertext }, {
            type: 'ciphertext',
            encKey: keys.clientEncKey,
            fixedIv: keys.clientIv,
            iv,
            recordNumber: recordSendCount,
            macKey,
            ciphertext,
            plaintext,
            contentType: opts.contentType,
        });
        recordSendCount += 1;
    }
    async function writePacket(opts) {
        logger.trace({ ...opts, data: (0, generics_1.toHexStringWithWhitespace)(opts.data) }, 'writing packet');
        const header = (0, packets_1.packPacketHeader)(opts.data.length, opts);
        await write({ header, content: opts.data }, { type: 'plaintext' });
    }
    async function end(error) {
        ended = true;
        await enqueueServerPacket(() => { });
        handshakeDone = false;
        handshakeMsgs = [];
        keys = undefined;
        recordSendCount = 0;
        recordRecvCount = 0;
        earlySecret = undefined;
        cipherSuite = undefined;
        keyType = undefined;
        clientRandom = undefined;
        serverRandom = undefined;
        processor.reset();
        onTlsEnd?.(error);
    }
    async function getKeyPair(keyType) {
        const algorithm = constants_1.SUPPORTED_NAMED_CURVE_MAP[keyType].algorithm;
        if (!keyPairs[keyType]) {
            keyPairs[keyType] = await crypto_1.crypto.generateKeyPair(algorithm);
        }
        return {
            algorithm,
            keyPair: keyPairs[keyType]
        };
    }
    return {
        getMetadata() {
            return {
                cipherSuite,
                keyType,
                version: connTlsVersion,
                selectedAlpn,
            };
        },
        hasEnded() {
            return ended;
        },
        /**
         * Get the current traffic keys
         */
        getKeys() {
            if (!keys) {
                return undefined;
            }
            return { ...keys, recordSendCount, recordRecvCount };
        },
        /**
         * Session ID used to connect to the server
         */
        getSessionId() {
            return sessionId;
        },
        isHandshakeDone() {
            return handshakeDone;
        },
        getPskFromTicket(ticket) {
            return (0, session_ticket_1.getPskFromTicket)(ticket, {
                masterKey: keys.masterSecret,
                hellos: handshakeMsgs,
                cipherSuite: cipherSuite,
            });
        },
        /**
         * Start the handshake with the server
         */
        async startHandshake(opts) {
            if (handshakeDone) {
                throw new Error('Handshake already done');
            }
            sessionId = crypto_1.crypto.randomBytes(32);
            ended = false;
            clientRandom = opts?.random || crypto_1.crypto.randomBytes(32);
            const clientHello = await (0, client_hello_1.packClientHello)({
                host,
                keysToShare: await Promise.all(namedCurves
                    .map(async (keyType) => {
                    const { keyPair } = await getKeyPair(keyType);
                    return {
                        type: keyType,
                        key: keyPair.pubKey,
                    };
                })),
                random: clientRandom,
                sessionId,
                psk: opts?.psk,
                cipherSuites,
                supportedProtocolVersions,
                signatureAlgorithms,
                applicationLayerProtocols,
            });
            handshakeMsgs.push(clientHello);
            if (opts?.psk) {
                earlySecret = opts.psk.earlySecret;
            }
            await writePacket({
                type: 'HELLO',
                data: clientHello,
            });
        },
        /**
         * Handle bytes received from the server.
         * Could be a complete or partial TLS packet
         */
        handleReceivedBytes(data) {
            processor.onData(data, processPacket);
        },
        /**
         * Handle a complete TLS packet received
         * from the server
         */
        handleReceivedPacket: processPacket,
        /**
         * Utilise the KeyUpdate handshake message to update
         * the traffic keys. Available only in TLS 1.3
         * @param requestUpdateFromServer should the server be requested to
         * update its keys as well
         */
        async updateTrafficKeys(requestUpdateFromServer = false) {
            const packet = (0, key_update_1.packKeyUpdateRecord)(requestUpdateFromServer
                ? 'UPDATE_REQUESTED'
                : 'UPDATE_NOT_REQUESTED');
            await writeEncryptedPacket({
                data: packet,
                type: 'WRAPPED_RECORD',
                contentType: 'HANDSHAKE'
            });
            const newMasterSecret = await (0, decryption_utils_1.computeUpdatedTrafficMasterSecret)(keys.clientSecret, cipherSuite);
            const newKeys = await (0, decryption_utils_1.deriveTrafficKeysForSide)(newMasterSecret, cipherSuite);
            keys = {
                ...keys,
                clientSecret: newMasterSecret,
                clientEncKey: newKeys.encKey,
                clientIv: newKeys.iv,
            };
            recordSendCount = 0;
            logger.info('updated client traffic keys');
        },
        async write(data) {
            if (!handshakeDone) {
                throw new Error('Handshake not done');
            }
            const chunks = (0, generics_1.chunkUint8Array)(data, constants_1.MAX_ENC_PACKET_SIZE);
            for (const chunk of chunks) {
                await writeEncryptedPacket({
                    data: chunk,
                    type: 'WRAPPED_RECORD',
                    contentType: 'APPLICATION_DATA'
                });
            }
        },
        end,
    };
}
exports.makeTLSClient = makeTLSClient;

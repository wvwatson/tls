import { Logger, ProcessPacket, TLSProtocolVersion } from '../types';
import { PACKET_TYPE } from './constants';
type PacketType = keyof typeof PACKET_TYPE;
export type PacketHeaderOptions = {
    type: PacketType;
    /**
     * TLS version to use in the header packet
     * */
    version?: TLSProtocolVersion;
};
export type PacketOptions = PacketHeaderOptions & {
    data: Uint8Array;
};
export declare function packPacketHeader(dataLength: number, { type, version }: PacketHeaderOptions): Uint8Array;
export declare function packPacket(opts: PacketOptions): Uint8Array;
/**
 * Packs data prefixed with the length of the data;
 * Length encoded UInt24 big endian
 */
export declare function packWith3ByteLength(data: Uint8Array): Uint8Array;
export declare function readWithLength(data: Uint8Array, lengthBytes?: number): Uint8Array | undefined;
/**
 * Read a prefix of the data, that is prefixed with the length of
 * said data. Throws an error if the data is not long enough
 *
 * @param data total data to read from
 * @param lengthBytes number of bytes to read the length from.
 * Default is 2 bytes
 */
export declare function expectReadWithLength(data: Uint8Array, lengthBytes?: number): Uint8Array;
/**
 * Packs data prefixed with the length of the data;
 * Length encoded UInt16 big endian
 */
export declare function packWithLength(data: Uint8Array): Uint8Array;
/**
 * Processes an incoming stream of TLS packets
 */
export declare function makeMessageProcessor(logger: Logger): {
    getPendingBuffer(): Uint8Array;
    /**
     * @param packet TLS packet;
     * can be multiple packets concatenated
     * or incomplete packet
     * or a single packet
     * @param onChunk handle a complete packet
     */
    onData(packet: Uint8Array, onChunk: ProcessPacket): void;
    reset(): void;
};
export {};

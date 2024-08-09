import * as peculiar from '@peculiar/x509';
import type { X509Certificate } from '../types';
export declare function loadX509FromPem(pem: string | Uint8Array): X509Certificate<peculiar.X509Certificate>;
export declare function loadX509FromDer(der: Uint8Array): X509Certificate<peculiar.X509Certificate>;

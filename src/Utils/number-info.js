/* Elaina Baileys maintained distribution. Upstream notices and license are preserved in LICENSE and NOTICE.md. */
import { Boom } from '@hapi/boom';
import { createHash, randomBytes, randomUUID } from 'crypto';
import http from 'http';
import https from 'https';
import tls from 'tls';
import { initAuthCreds } from './auth-utils.js';

const CALLING_CODES = new Set('1,7,20,27,30,31,32,33,34,36,39,40,41,43,44,45,46,47,48,49,51,52,53,54,55,56,57,58,60,61,62,63,64,65,66,81,82,84,86,90,91,92,93,94,95,98,211,212,213,216,218,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,248,249,250,251,252,253,254,255,256,257,258,260,261,262,263,264,265,266,267,268,269,290,291,297,298,299,350,351,352,353,354,355,356,357,358,359,370,371,372,373,374,375,376,377,378,380,381,382,383,385,386,387,389,420,421,423,500,501,502,503,504,505,506,507,508,509,590,591,592,593,594,595,596,597,598,599,670,672,673,674,675,676,677,678,679,680,681,682,683,685,686,687,688,689,690,691,692,850,852,853,855,856,880,886,960,961,962,963,964,965,966,967,968,970,971,972,973,974,975,976,977,992,993,994,995,996,998'.split(','));
const CODE_ENDPOINT = 'https://v.whatsapp.net/v2/code';

/**
 * The registration token is an md5 over a per-version secret, the hex md5 of
 * the app version, and the national number — same shape the Android client
 * signs its /v2/code request with. Version 2.26.36.74 (App Store 26.36.74
 * mapped back to the four-part scheme) is accepted as of 2026-09; when the
 * server starts answering reason "old_version", bump WA_VERSION (and only
 * then — the secret stays valid across version bumps). Verified live: with
 * this token the server validates the request past its bad_token gate.
 */
const WA_VERSION = '2.26.36.74';
const MOBILE_TOKEN_SECRET = '0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM';
const MOBILE_TOKEN_KEY = Buffer.from(MOBILE_TOKEN_SECRET + createHash('md5').update(WA_VERSION).digest('hex'));
export const DEFAULT_REGISTRATION_UA = `WhatsApp/${WA_VERSION} iOS/18.2 Device/Apple-iPhone_13`;

export const splitCallingCode = (phoneNumber) => {
    const digits = String(phoneNumber ?? '').replace(/\D/g, '');
    for (let length = 3; length >= 1; length--) {
        const code = digits.slice(0, length);
        if (code.length === length && CALLING_CODES.has(code)) {
            return { countryCode: code, nationalNumber: digits.slice(length).replace(/^0+/, '') };
        }
    }
    return { countryCode: '', nationalNumber: digits.replace(/^0+/, '') };
};

export const maskNationalNumber = (nationalNumber) => {
    const digits = String(nationalNumber ?? '').replace(/\D/g, '');
    if (digits.length <= 5) {
        return digits;
    }
    return digits.slice(0, 2) + '*'.repeat(digits.length - 5) + digits.slice(-3);
};

const toBase64Url = (bytes) => Buffer.from(bytes).toString('base64url');
const toPercentHex = (bytes) => Buffer.from(bytes).toString('hex').match(/.{1,2}/g).map(byte => `%${byte.toLowerCase()}`).join('');
const urlencode = (value) => String(value).replace(/-/g, '%2d').replace(/_/g, '%5f').replace(/~/g, '%7e');

const probeViaProxy = (url, headers, proxy, timeoutMs) => new Promise((resolve, reject) => {
    const target = new URL(url);
    const proxyUrl = new URL(proxy);
    const auth = proxyUrl.username
        ? `Basic ${Buffer.from(`${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`).toString('base64')}`
        : undefined;
    const connect = http.request({
        host: proxyUrl.hostname,
        port: Number(proxyUrl.port) || 80,
        method: 'CONNECT',
        path: `${target.hostname}:443`,
        headers: { Host: `${target.hostname}:443`, ...(auth ? { 'Proxy-Authorization': auth } : {}) }
    });
    connect.setTimeout(timeoutMs, () => connect.destroy(new Error('proxy connect timed out')));
    connect.on('error', reject);
    connect.on('connect', (response, socket) => {
        if (response.statusCode !== 200) {
            socket.destroy();
            reject(new Boom(`proxy refused CONNECT with ${response.statusCode}`, { statusCode: 502, data: { proxy } }));
            return;
        }
        const request = https.request({
            createConnection: () => tls.connect({ socket, servername: target.hostname }),
            host: target.hostname,
            port: 443,
            path: `${target.pathname}${target.search}`,
            method: 'GET',
            headers,
            timeout: timeoutMs
        });
        request.on('error', (error) => {
            socket.destroy();
            reject(error);
        });
        request.on('response', (proxied) => {
            const chunks = [];
            proxied.on('data', chunk => chunks.push(chunk));
            proxied.on('end', () => resolve({ status: proxied.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
            proxied.on('error', reject);
        });
        request.end();
    });
    connect.end();
});

/**
 * The /v2/code probe mirrors the Android registration request (the ban
 * checker services use the same surface): a BANNED number answers with
 * appeal_token / violation_type / in_app_ban_appeal, a RESTRICTED one with
 * custom_block_screen or reason "blocked", a clean one with status "sent"
 * or "ok". Asking with method "wa_old" additionally leaks the primary
 * device name (wa_old_device_name) and the masked recovery email of the
 * account — the data the "check wa" tools sell. Side effect, inherent to
 * the probe: WhatsApp dispatches an OTP notification to the number.
 */
export const checkNumberInfo = async (phoneNumber, opts = {}) => {
    const digits = String(phoneNumber ?? '').replace(/\D/g, '');
    let countryCode;
    let nationalNumber;
    if (opts.countryCode) {
        countryCode = String(opts.countryCode).replace(/\D/g, '');
        nationalNumber = (digits.startsWith(countryCode) ? digits.slice(countryCode.length) : digits).replace(/^0+/, '');
    }
    else {
        if (!digits || digits.startsWith('0') || digits.length < 7 || digits.length > 15) {
            throw new Boom('phoneNumber must be in international format: country code followed by the national number, digits only', { statusCode: 400, data: { phoneNumber } });
        }
        ({ countryCode, nationalNumber } = splitCallingCode(digits));
    }
    if (!countryCode || !nationalNumber || nationalNumber.length < 4) {
        throw new Boom('could not determine the country calling code; pass opts.countryCode explicitly', { statusCode: 400, data: { phoneNumber } });
    }
    const creds = initAuthCreds();
    const method = opts.method ?? 'wa_old';
    const token = createHash('md5')
        .update(Buffer.concat([MOBILE_TOKEN_KEY, Buffer.from(nationalNumber, 'utf8')]))
        .digest('hex');
    const query = {
        cc: countryCode,
        in: nationalNumber,
        Rc: '0',
        lg: opts.language ?? 'en',
        lc: opts.locale ?? 'GB',
        mistyped: '6',
        authkey: toBase64Url(creds.noiseKey.public),
        e_regid: toBase64Url(Buffer.from(creds.registrationId.toString(16).padStart(8, '0').match(/../g).map(byte => Number.parseInt(byte, 16)))),
        e_keytype: 'BQ',
        e_ident: toBase64Url(creds.signedIdentityKey.public),
        e_skey_id: 'AAAA',
        e_skey_val: toBase64Url(creds.signedPreKey.keyPair.public),
        e_skey_sig: toBase64Url(creds.signedPreKey.signature),
        fdid: randomUUID(),
        network_ratio_type: '1',
        expid: toBase64Url(Buffer.from(randomUUID().replace(/-/g, ''), 'hex')),
        simnum: '1',
        hasinrc: '1',
        pid: String(Math.floor(Math.random() * 1000)),
        id: toPercentHex(randomBytes(20)),
        backup_token: toPercentHex(randomBytes(20)),
        token,
        mcc: String(opts.mcc ?? '510').padStart(3, '0'),
        mnc: String(opts.mnc ?? '10').padStart(3, '0'),
        sim_mcc: '000',
        sim_mnc: '000',
        method,
        reason: '',
        hasav: '1'
    };
    const qs = Object.entries(query)
        .filter(([, value]) => value !== null && value !== undefined)
        .map(([key, value]) => `${key}=${urlencode(value)}`)
        .join('&');
    const requestUrl = `${CODE_ENDPOINT}?${qs}`;
    const headers = {
        'Accept': 'application/json',
        'User-Agent': opts.userAgent ?? DEFAULT_REGISTRATION_UA
    };
    const timeoutMs = opts.timeoutMs ?? 20000;
    const proxyPool = opts.proxies ?? (opts.proxy ? [opts.proxy] : []);
    const maxAttempts = proxyPool.length ? Math.max(1, opts.retries ?? 5) : 1;
    const throttled = new Set(['no_routes', 'temporarily_unavailable', 'too_many']);
    let json;
    let attempts = 0;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        attempts = attempt + 1;
        const proxy = proxyPool.length ? proxyPool[attempt % proxyPool.length] : undefined;
        let response;
        try {
            response = proxy
                ? await probeViaProxy(requestUrl, headers, proxy, timeoutMs)
                : await fetch(requestUrl, { headers, signal: AbortSignal.timeout(timeoutMs) });
        }
        catch (error) {
            if (attempt + 1 >= maxAttempts) {
                throw new Boom(`could not reach the registration server: ${error?.message ?? error}`, { statusCode: 502, data: { phoneNumber, cause: error } });
            }
            await new Promise(resolve => setTimeout(resolve, 500));
            continue;
        }
        const text = typeof response.text === 'string' ? response.text : await response.text();
        try {
            json = JSON.parse(text);
        }
        catch {
            throw new Boom(`registration server returned HTTP ${response.status} with a non-JSON body`, { statusCode: response.status >= 400 ? response.status : 502, data: { phoneNumber, body: text.slice(0, 512) } });
        }
        const incomplete = method === 'wa_old'
            && ['ok', 'sent'].includes(json.status ?? '')
            && !json.wa_old_device_name
            && !json.email;
        if (attempt + 1 < maxAttempts && (throttled.has(json.reason ?? '') || (opts.retryUntilDeviceInfo !== false && incomplete))) {
            await new Promise(resolve => setTimeout(resolve, 750));
            continue;
        }
        break;
    }
    const status = json.status;
    const reason = json.reason ?? null;
    const banned = Boolean(json.appeal_token) || Boolean(json.violation_type);
    const restricted = !banned && (Boolean(json.custom_block_screen) || reason === 'blocked');
    const clean = ['ok', 'sent'].includes(status);
    const label = banned ? 'Banned'
        : restricted ? 'Restricted'
            : clean ? 'Safe'
                : ['temporarily_unavailable', 'too_recent', 'too_many'].includes(reason) ? 'Unavailable'
                    : 'Unknown';
    const appealToken = json.appeal_token || null;
    const canAppeal = typeof json.in_app_ban_appeal === 'number' ? json.in_app_ban_appeal !== 0 : null;
    return {
        data: {
            number: maskNationalNumber(nationalNumber),
            countryCode,
            status: label,
            registered: banned || restricted ? true : clean && method === 'wa_old' ? true : null,
            banned,
            restricted,
            reason,
            violationType: json.violation_type || null,
            canAppeal,
            appealToken,
            attempts,
            info: {
                device: json.wa_old_device_name || null,
                email: json.email || null,
                lid: json.lid || null,
                violatedPolicy: json.violated_policy || null,
                violationReason: json.violation_reason || null,
                retryAfter: json.retry_after ?? null,
                serverStatus: status ?? null,
                method
            },
            raw: json
        }
    };
};

/* Elaina Baileys maintained distribution. Upstream notices and license are preserved in LICENSE and NOTICE.md. */
import { Boom } from '@hapi/boom';
import { randomBytes, randomUUID } from 'crypto';
import { encodeBigEndian } from './generics.js';
import { initAuthCreds } from './auth-utils.js';

const CALLING_CODES = new Set('1,7,20,27,30,31,32,33,34,36,39,40,41,43,44,45,46,47,48,49,51,52,53,54,55,56,57,58,60,61,62,63,64,65,66,81,82,84,86,90,91,92,93,94,95,98,211,212,213,216,218,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,248,249,250,251,252,253,254,255,256,257,258,260,261,262,263,264,265,266,267,268,269,290,291,297,298,299,350,351,352,353,354,355,356,357,358,359,370,371,372,373,374,375,376,377,378,380,381,382,383,385,386,387,389,420,421,423,500,501,502,503,504,505,506,507,508,509,590,591,592,593,594,595,596,597,598,599,670,672,673,674,675,676,677,678,679,680,681,682,683,685,686,687,688,689,690,691,692,850,852,853,855,856,880,886,960,961,962,963,964,965,966,967,968,970,971,972,973,974,975,976,977,992,993,994,995,996,998'.split(','));
const EXIST_ENDPOINT = 'https://v.whatsapp.net/v2/exist';
export const DEFAULT_REGISTRATION_UA = 'WhatsApp/2.26.37.71 Android/15 Device/Samsung-SM-S928B';

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

const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const uuidToBase64 = () => {
    const hex = randomUUID().replace(/-/g, '');
    return toBase64(Buffer.from(hex, 'hex'));
};

/**
 * The registration endpoint validates the User-Agent before it accepts the
 * platform param, and expects the raw 32-byte Curve25519 keys: the 0x05
 * libsignal prefix is rejected by the current server for e_ident/e_skey_val,
 * while e_keytype carries the prefix byte alone. Verified live against
 * v.whatsapp.net and against com.whatsapp 2.26.37.71 (KotlinRegistrationBridge).
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
    const body = new URLSearchParams({
        cc: countryCode,
        in: nationalNumber,
        platform: 'Android',
        lg: opts.language ?? 'en',
        lc: opts.locale ?? 'US',
        fdid: randomUUID(),
        expid: uuidToBase64(),
        id: randomBytes(20).toString('hex'),
        login: countryCode + nationalNumber,
        type: '0',
        authkey: toBase64(creds.noiseKey.public),
        e_ident: toBase64(creds.signedIdentityKey.public),
        e_keytype: toBase64(Buffer.from([5])),
        e_regid: toBase64(encodeBigEndian(creds.registrationId, 4)),
        e_skey_id: toBase64(encodeBigEndian(creds.signedPreKey.keyId, 3)),
        e_skey_val: toBase64(creds.signedPreKey.keyPair.public),
        e_skey_sig: toBase64(creds.signedPreKey.signature)
    }).toString();
    let response;
    try {
        response = await fetch(EXIST_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'User-Agent': opts.userAgent ?? DEFAULT_REGISTRATION_UA
            },
            body,
            signal: AbortSignal.timeout(opts.timeoutMs ?? 20000)
        });
    }
    catch (error) {
        throw new Boom(`could not reach the registration server: ${error?.message ?? error}`, { statusCode: 502, data: { phoneNumber, cause: error } });
    }
    const text = await response.text();
    let json;
    try {
        json = JSON.parse(text);
    }
    catch {
        throw new Boom(`registration server returned HTTP ${response.status} with a non-JSON body`, { statusCode: response.status >= 400 ? response.status : 502, data: { phoneNumber, body: text.slice(0, 512) } });
    }
    const status = json.status;
    const reason = json.reason ?? null;
    const banned = status === 'fail'
        && (reason === 'blocked' || Boolean(json.violation_type) || Boolean(json.violated_policy) || Boolean(json.custom_block_screen));
    const registered = status === 'ok';
    const label = banned ? 'Banned' : registered ? 'Safe' : reason === 'incorrect' ? 'Not Registered' : 'Unknown';
    return {
        data: {
            number: maskNationalNumber(nationalNumber),
            countryCode,
            status: label,
            banned,
            registered,
            info: {
                device: json.wa_old_device_name || null,
                email: json.email || null,
                lid: json.lid || null,
                reason,
                violationType: json.violation_type || null,
                violatedPolicy: json.violated_policy || null,
                violationReason: json.violation_reason || null,
                isDeviceTrusted: typeof json.is_device_trusted === 'boolean' ? json.is_device_trusted : null,
                inAppBanAppeal: typeof json.in_app_ban_appeal === 'number' ? json.in_app_ban_appeal : null,
                retryAfter: json.retry_after ?? null,
                serverStatus: status ?? null
            }
        }
    };
};

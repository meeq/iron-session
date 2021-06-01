"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IronStore = exports.IronSession = exports.getIronSession = void 0;
// Dependency imports
const iron_1 = __importDefault(require("@hapi/iron"));
const clone_1 = __importDefault(require("clone"));
const cookie_1 = __importDefault(require("cookie"));
/**
 * Number of seconds of permitted clock skew for incoming expirations
 * @see https://hapi.dev/family/iron/api/?v=6.0.0#options
 */
const TIMESTAMP_SKEW_SEC = 60; // 1 minute
const MAX_TTL = 2147483647; // 2^31 seconds
const DEFAULT_TTL = 30 * 24 * 60 * 60; // 30 days (in seconds)
const MAX_COOKIE_SIZE = 4096; // 4 Kilobytes
const DEFAULT_COOKIE_OPTIONS = {
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
};
async function getIronSession(req, res, sessionOptions) {
    const session = new IronSession(req, res, sessionOptions);
    await session.restore();
    return session;
}
exports.getIronSession = getIronSession;
class IronSession {
    constructor(req, res, sessionOptions) {
        this.req = req;
        this.res = res;
        // Handle sessionOptions
        this.cookieName = getCookieName(sessionOptions);
        this.cookieOptions = getCookieSerializeOptions(sessionOptions);
        const password = getPassword(sessionOptions);
        const ttl = sessionOptions?.ttl ?? DEFAULT_TTL;
        // Setup the IronStore that backs this session
        const store = new IronStore(password, ttl);
        this.get = store.get.bind(store);
        this.set = store.set.bind(store);
        this.unset = store.unset.bind(store);
        this.clear = store.clear.bind(store);
        this.store = store;
    }
    readCookie() {
        return getRequestCookie(this.req, this.cookieName);
    }
    writeCookie(value) {
        // Immediately expire the cookie if it has no value
        const options = value ? this.cookieOptions : { ...this.cookieOptions, maxAge: 0 };
        const serialized = cookie_1.default.serialize(this.cookieName, value, options);
        // Fail if the cookie is too large for browsers
        if (serialized.length > MAX_COOKIE_SIZE) {
            throw new Error(`IronSession cookie length is too big: ${serialized.length}`);
        }
        setResponseCookie(this.res, serialized);
    }
    async restore() {
        const sealed = this.readCookie();
        if (sealed) {
            return this.store.unseal(sealed);
        }
        return false;
    }
    async save() {
        this.writeCookie(await this.store.seal());
    }
    destroy() {
        this.store.clear();
        this.writeCookie('');
    }
}
exports.IronSession = IronSession;
class IronStore {
    constructor(password, ttl) {
        this.sealPassword = IronStore.normalizeSealPassword(password);
        this.unsealPassword = IronStore.normalizeUnsealPassword(password);
        // Convert TTL in seconds to milliseconds for Iron options
        this.sealOptions = { ...iron_1.default.defaults, ttl: ttl * 1000 };
        this.unsealed = {};
    }
    get(key) {
        return clone_1.default(this.unsealed[key]);
    }
    set(key, value) {
        this.unsealed[key] = clone_1.default(value);
    }
    unset(key) {
        delete this.unsealed[key];
    }
    clear() {
        this.unsealed = {};
    }
    async seal() {
        return iron_1.default.seal(this.unsealed, this.sealPassword, this.sealOptions);
    }
    async unseal(sealed) {
        try {
            const unsealed = await iron_1.default.unseal(sealed, this.unsealPassword, this.sealOptions);
            this.unsealed = unsealed;
            return true;
        }
        catch (err) {
            if (
            // Ignore "normal" errors that just mean the seal is no longer valid
            err.message !== 'Expired seal' &&
                err.message !== 'Bad hmac value' &&
                !err.message.startsWith('Cannot find password: ')) {
                throw err;
            }
            return false;
        }
    }
    static normalizeSealPassword(denormalized) {
        if (!denormalized.length) {
            throw new Error('Empty IronStore argument: `password`');
        }
        if (typeof denormalized === 'string') {
            return { id: '1', secret: denormalized };
        }
        return denormalized[0];
    }
    static normalizeUnsealPassword(denormalized) {
        if (!denormalized.length) {
            throw new Error('Empty IronStore argument: `password`');
        }
        if (typeof denormalized === 'string') {
            return { 1: denormalized };
        }
        const normalized = {};
        for (const { id, secret } of denormalized) {
            normalized[id] = secret;
        }
        return normalized;
    }
}
exports.IronStore = IronStore;
function getCookieName(sessionOptions) {
    if (sessionOptions?.cookieName?.length) {
        return sessionOptions.cookieName;
    }
    const envCookieName = process.env.IRON_SESSION_COOKIE_NAME;
    if (envCookieName) {
        return envCookieName;
    }
    throw new Error('Missing IronSession option: `cookieName`');
}
function getPassword(sessionOptions) {
    if (sessionOptions?.password?.length) {
        return sessionOptions.password;
    }
    const envPassword = process.env.IRON_SESSION_PASSWORD;
    if (envPassword) {
        return envPassword;
    }
    throw new Error('Missing IronSession option: `password`');
}
function getCookieSerializeOptions(sessionOptions) {
    return {
        ...DEFAULT_COOKIE_OPTIONS,
        ...sessionOptions?.cookieOptions,
        maxAge: getCookieMaxAge(sessionOptions),
    };
}
function getCookieMaxAge(sessionOptions) {
    if (sessionOptions?.cookieOptions?.maxAge) {
        return Math.min(sessionOptions.cookieOptions.maxAge, MAX_TTL);
    }
    /**
     * Ensure the client expires the cookie before the seal is expired server-side.
     * It also allows for clock difference between server and clients.
     */
    const ttl = sessionOptions?.ttl ?? DEFAULT_TTL;
    return Math.min(ttl - TIMESTAMP_SKEW_SEC, MAX_TTL);
}
function getRequestCookie(req, cookieName) {
    // Prefer cookies that were implicitly parsed by the web framework if available
    if (typeof req.cookies !== 'undefined') {
        return req.cookies[cookieName];
    }
    // Fallback for requests that do not have implicitly parsed cookies
    const cookies = cookie_1.default.parse(req.headers['cookie'] || '');
    return cookies[cookieName];
}
function setResponseCookie(res, serializedCookie) {
    const existingSetCookies = [res.getHeader('set-cookie') || []].flat().map(String);
    res.setHeader('set-cookie', [...existingSetCookies, serializedCookie]);
}
//# sourceMappingURL=index.js.map
// Node Standard Library imports
import type { IncomingMessage, OutgoingMessage } from 'http';
// Dependency imports
import Iron from '@hapi/iron';
import clone from 'clone';
import cookie from 'cookie';

/**
 * Number of seconds of permitted clock skew for incoming expirations
 * @see https://hapi.dev/family/iron/api/?v=6.0.0#options
 */
const TIMESTAMP_SKEW_SEC = 60; // 1 minute
const MAX_TTL = 2147483647; // 2^31 seconds
const DEFAULT_TTL = 30 * 24 * 60 * 60; // 30 days (in seconds)
const MAX_COOKIE_SIZE = 4096; // 4 Kilobytes

const DEFAULT_COOKIE_OPTIONS: Readonly<cookie.CookieSerializeOptions> = {
  httpOnly: true,
  path: '/',
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
};

type Request = IncomingMessage & {
  cookies?: { [key: string]: string };
};
type Response = OutgoingMessage;

type IronUnsealPassword = Iron.password.Hash;
type IronSealPassword = Iron.password.Secret;
type IronDenormalizedPassword = string | { id: string; secret: string }[];

export type IronSessionOptions = {
  /**
   * Name of the session cookie
   *
   * If not provided, IRON_SESSION_COOKIE_NAME environment variable will be used.
   */
  cookieName?: string;

  /**
   * Options for the cookie
   */
  cookieOptions?: cookie.CookieSerializeOptions;

  /**
   * Password for the store.
   *
   * If not provided, IRON_SESSION_PASSWORD environment variable will be used.
   */
  password?: IronDenormalizedPassword;

  /**
   * Time-to-live (in seconds)
   */
  ttl?: number;
};

export async function getIronSession<P = unknown>(
  req: Request,
  res: Response,
  sessionOptions?: IronSessionOptions,
): Promise<IronSession<P>> {
  const session = new IronSession<P>(req, res, sessionOptions);
  await session.restore();
  return session;
}

export class IronSession<P = unknown> {
  private store: IronStore<P>;
  private req: Request;
  private res: Response;
  private cookieName: string;
  private cookieOptions: cookie.CookieSerializeOptions;

  get: IronStore<P>['get'];
  set: IronStore<P>['set'];
  unset: IronStore<P>['unset'];
  clear: IronStore<P>['clear'];

  constructor(req: Request, res: Response, sessionOptions?: IronSessionOptions) {
    this.req = req;
    this.res = res;
    // Handle sessionOptions
    this.cookieName = getCookieName(sessionOptions);
    this.cookieOptions = getCookieSerializeOptions(sessionOptions);
    const password = getPassword(sessionOptions);
    const ttl = sessionOptions?.ttl ?? DEFAULT_TTL;
    // Setup the IronStore that backs this session
    const store = new IronStore<P>(password, ttl);
    this.get = store.get.bind(store);
    this.set = store.set.bind(store);
    this.unset = store.unset.bind(store);
    this.clear = store.clear.bind(store);
    this.store = store;
  }

  private readCookie(): string | undefined {
    return getRequestCookie(this.req, this.cookieName);
  }

  private writeCookie(value: string): void {
    // Immediately expire the cookie if it has no value
    const options = value ? this.cookieOptions : { ...this.cookieOptions, maxAge: 0 };
    const serialized = cookie.serialize(this.cookieName, value, options);
    // Fail if the cookie is too large for browsers
    if (serialized.length > MAX_COOKIE_SIZE) {
      throw new Error(`IronSession cookie length is too big: ${serialized.length}`);
    }
    setResponseCookie(this.res, serialized);
  }

  async restore(): Promise<boolean> {
    const sealed = this.readCookie();
    if (sealed) {
      return this.store.unseal(sealed);
    }
    return false;
  }

  async save(): Promise<void> {
    this.writeCookie(await this.store.seal());
  }

  destroy(): void {
    this.store.clear();
    this.writeCookie('');
  }
}

export class IronStore<P = unknown> {
  private unsealed: P;
  private sealPassword: IronSealPassword;
  private unsealPassword: IronUnsealPassword;
  private sealOptions: Iron.SealOptions;

  constructor(password: IronDenormalizedPassword, ttl: number) {
    this.sealPassword = IronStore.normalizeSealPassword(password);
    this.unsealPassword = IronStore.normalizeUnsealPassword(password);
    // Convert TTL in seconds to milliseconds for Iron options
    this.sealOptions = { ...Iron.defaults, ttl: ttl * 1000 };
    this.unsealed = {} as P;
  }

  get<K extends keyof P>(key: K): P[K] | undefined {
    return clone(this.unsealed[key]);
  }

  set<K extends keyof P>(key: K, value: P[K]): void {
    this.unsealed[key] = clone(value);
  }

  unset<K extends keyof P>(key: K): void {
    delete this.unsealed[key];
  }

  clear(): void {
    this.unsealed = {} as P;
  }

  async seal(): Promise<string> {
    return Iron.seal(this.unsealed, this.sealPassword, this.sealOptions);
  }

  async unseal(sealed: string): Promise<boolean> {
    try {
      const unsealed = await Iron.unseal(sealed, this.unsealPassword, this.sealOptions);
      this.unsealed = unsealed as P;
      return true;
    } catch (err) {
      if (
        // Ignore "normal" errors that just mean the seal is no longer valid
        err.message !== 'Expired seal' &&
        err.message !== 'Bad hmac value' &&
        !err.message.startsWith('Cannot find password: ')
      ) {
        throw err;
      }
      return false;
    }
  }

  static normalizeSealPassword(denormalized: IronDenormalizedPassword): IronSealPassword {
    if (!denormalized.length) {
      throw new Error('Empty IronStore argument: `password`');
    }
    if (typeof denormalized === 'string') {
      return { id: '1', secret: denormalized };
    }
    return denormalized[0] as IronSealPassword;
  }

  static normalizeUnsealPassword(denormalized: IronDenormalizedPassword): IronUnsealPassword {
    if (!denormalized.length) {
      throw new Error('Empty IronStore argument: `password`');
    }
    if (typeof denormalized === 'string') {
      return { 1: denormalized };
    }
    const normalized: IronUnsealPassword = {};
    for (const { id, secret } of denormalized) {
      normalized[id] = secret;
    }
    return normalized;
  }
}

function getCookieName(sessionOptions?: IronSessionOptions): string {
  if (sessionOptions?.cookieName?.length) {
    return sessionOptions.cookieName;
  }
  const envCookieName = process.env.IRON_SESSION_COOKIE_NAME;
  if (envCookieName) {
    return envCookieName;
  }
  throw new Error('Missing IronSession option: `cookieName`');
}

function getPassword(sessionOptions?: IronSessionOptions): IronDenormalizedPassword {
  if (sessionOptions?.password?.length) {
    return sessionOptions.password;
  }
  const envPassword = process.env.IRON_SESSION_PASSWORD;
  if (envPassword) {
    return envPassword;
  }
  throw new Error('Missing IronSession option: `password`');
}

function getCookieSerializeOptions(
  sessionOptions?: IronSessionOptions,
): cookie.CookieSerializeOptions {
  return {
    ...DEFAULT_COOKIE_OPTIONS,
    ...sessionOptions?.cookieOptions,
    maxAge: getCookieMaxAge(sessionOptions),
  };
}

function getCookieMaxAge(sessionOptions?: IronSessionOptions): number {
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

function getRequestCookie(req: Request, cookieName: string): string | undefined {
  // Prefer cookies that were implicitly parsed by the web framework if available
  if (typeof req.cookies !== 'undefined') {
    return req.cookies[cookieName];
  }
  // Fallback for requests that do not have implicitly parsed cookies
  const cookies = cookie.parse(req.headers['cookie'] || '');
  return cookies[cookieName];
}

function setResponseCookie(res: Response, serializedCookie: string): void {
  const existingSetCookies = [res.getHeader('set-cookie') || []].flat().map(String);
  res.setHeader('set-cookie', [...existingSetCookies, serializedCookie]);
}

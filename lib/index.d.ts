/// <reference types="node" />
import type { IncomingMessage, OutgoingMessage } from 'http';
import Iron from '@hapi/iron';
import cookie from 'cookie';
declare type Request = IncomingMessage & {
    cookies?: {
        [key: string]: string;
    };
};
declare type Response = OutgoingMessage;
declare type IronUnsealPassword = Iron.password.Hash;
declare type IronSealPassword = Iron.password.Secret;
declare type IronDenormalizedPassword = string | {
    id: string;
    secret: string;
}[];
export declare type IronSessionOptions = {
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
export declare function getIronSession<P = unknown>(req: Request, res: Response, sessionOptions?: IronSessionOptions): Promise<IronSession<P>>;
export declare class IronSession<P = unknown> {
    private store;
    private req;
    private res;
    private cookieName;
    private cookieOptions;
    get: IronStore<P>['get'];
    set: IronStore<P>['set'];
    unset: IronStore<P>['unset'];
    clear: IronStore<P>['clear'];
    constructor(req: Request, res: Response, sessionOptions?: IronSessionOptions);
    private readCookie;
    private writeCookie;
    restore(): Promise<boolean>;
    save(): Promise<void>;
    destroy(): void;
}
export declare class IronStore<P = unknown> {
    private unsealed;
    private sealPassword;
    private unsealPassword;
    private sealOptions;
    constructor(password: IronDenormalizedPassword, ttl: number);
    get<K extends keyof P>(key: K): P[K] | undefined;
    set<K extends keyof P>(key: K, value: P[K]): void;
    unset<K extends keyof P>(key: K): void;
    clear(): void;
    seal(): Promise<string>;
    unseal(sealed: string): Promise<boolean>;
    static normalizeSealPassword(denormalized: IronDenormalizedPassword): IronSealPassword;
    static normalizeUnsealPassword(denormalized: IronDenormalizedPassword): IronUnsealPassword;
}
export {};

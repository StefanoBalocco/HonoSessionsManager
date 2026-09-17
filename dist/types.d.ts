export type Undefinedable<T> = T | undefined;
export type Promisable<T> = T | Promise<T>;
export type JSONValue = string | number | boolean | null | {
    [key: string]: JSONValue;
} | JSONValue[];
export type Session = {
    readonly data: {
        get(key: string): Promisable<Undefinedable<JSONValue>>;
        set(key: string, value: JSONValue): Promisable<boolean>;
        delete(key: string): Promisable<boolean>;
    };
};

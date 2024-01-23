export class Debug {

  public static get enabled(): boolean {
    return typeof self !== "undefined" && (self as any).PV_WEBCRYPTO_LINER_LOG;
  }

  public static log(message?: any, ...optionalParams: any[]): void;
  public static log(...args: any[]): void {
    if (this.enabled) {
      console.log(...args);
    }
  }

  public static error(message?: any, ...optionalParams: any[]): void;
  public static error(...args: any[]): void {
    if (this.enabled) {
      console.error(...args);
    }
  }

  public static info(message?: any, ...optionalParams: any[]): void;
  public static info(...args: any[]): void {
    if (this.enabled) {
      console.info(...args);
    }
  }

  public static warn(message?: any, ...optionalParams: any[]): void;
  public static warn(...args: any[]): void {
    if (this.enabled) {
      console.warn(...args);
    }
  }

  public static trace(message?: any, ...optionalParams: any[]): void;
  public static trace(...args: any[]): void {
    if (this.enabled) {
      console.trace(...args);
    }
  }

}

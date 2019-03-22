export class Debug {

  public static get enabled() {
    return typeof self !== "undefined" && (self as any).PV_WEBCRYPTO_LINER_LOG;
  }

  public static log(message?: any, ...optionalParams: any[]) {
    if (this.enabled) {
      console.log.apply(console, arguments);
    }
  }

  public static error(message?: any, ...optionalParams: any[]) {
    if (this.enabled) {
      console.error.apply(console, arguments);
    }
  }

  public static info(message?: any, ...optionalParams: any[]) {
    if (this.enabled) {
      console.info.apply(console, arguments);
    }
  }

  public static warn(message?: any, ...optionalParams: any[]) {
    if (this.enabled) {
      console.warn.apply(console, arguments);
    }
  }

  public static trace(message?: any, ...optionalParams: any[]) {
    if (this.enabled) {
      console.trace.apply(console, arguments);
    }
  }

}

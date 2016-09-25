namespace webcrypto.liner {

    export let Browser = {
        IE: "Internet Explorer",
        Safari: "Safari",
        Edge: "Edge",
        Chrome: "Chrome",
        Firefox: "Firefox Mozilla",
    };

    /**
     * Returns info about browser 
     */
    export function BrowserInfo() {
        let res = {
            name: "",
            version: ""
        };
        const userAgent = window.navigator.userAgent;

        let reg: RegExpExecArray | null;
        if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
            res.name = Browser.Edge;
            res.version = reg[1];
        } else if (/msie/i.test(userAgent)) {
            res.name = Browser.IE;
            res.version = /msie ([\d\.]+)/i.exec(userAgent)![1];
        } else if (/chrome/i.test(userAgent)) {
            res.name = Browser.Chrome;
            res.version = /chrome\/([\d\.]+)/i.exec(userAgent)![1];
        } else if (/safari/i.test(userAgent)) {
            res.name = Browser.Safari;
            res.version = /([\d\.]+) safari/i.exec(userAgent)![1];
        } else if (/firefox/i.test(userAgent)) {
            res.name = Browser.Firefox;
            res.version = /firefox\/([\d\.]+)/i.exec(userAgent)![1];
        }
        return res;
    }

    export function string2buffer(binaryString: string) {
        let res = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++)
            res[i] = binaryString.charCodeAt(i);
        return res;
    }

    export function buffer2string(buffer: Uint8Array) {
        let res = "";
        for (let i = 0; i < buffer.length; i++)
            res += String.fromCharCode(buffer[i]);
        return res;
    }

    export function concat(...buf: Uint8Array[]) {
        const res = new Uint8Array(buf.map(item => item.length).reduce((prev, cur) => prev + cur));
        let offset = 0;
        buf.forEach((item, index) => {
            for (let i = 0; i < item.length; i++)
                res[offset + i] = item[i];
            offset += item.length;
        });
        return res;
    }
}

; +function () {
    var Browser = {
        IE: "Internet Explorer",
        Safari: "Safari",
        Edge: "Edge",
        Chrome: "Chrome",
        Firefox: "Firefox Mozilla",
    };

    /**
     * Returns info about browser 
     */
    function BrowserInfo() {
        var res = {
            name: "",
            version: ""
        };
        const userAgent = self.navigator.userAgent;

        var reg;
        if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
            res.name = Browser.Edge;
            res.version = reg[1];
        } else if (/msie/i.test(userAgent)) {
            res.name = Browser.IE;
            res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
        } else if (/Trident/i.test(userAgent)) {
            res.name = Browser.IE;
            res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
        } else if (/chrome/i.test(userAgent)) {
            res.name = Browser.Chrome;
            res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
        } else if (/safari/i.test(userAgent)) {
            res.name = Browser.Safari;
            res.version = /([\d\.]+) safari/i.exec(userAgent)[1];
        } else if (/firefox/i.test(userAgent)) {
            res.name = Browser.Firefox;
            res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
        }
        return res;
    }

    function importScript(src) {
        var script = document.createElement("script");
        script.setAttribute("src", src);

        document.head.appendChild(script);
    }

    // init JS libs

    if (!self.Promise) {
        importScript("src/promise.min.js")
    }
    importScript("src/webcrypto-liner.shim.min.js")

    var browserInfo = BrowserInfo();
    var browserName = browserInfo.name;

    if (browserName === Browser.IE ||
        browserName === Browser.Edge ||
        browserName === Browser.Safari) {
        importScript("src/elliptic.min.js")
        importScript("src/asmcrypto.min.js")
    }
}();
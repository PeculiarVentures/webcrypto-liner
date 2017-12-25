//**************************************************************************************
const Browser = {
	IE: "Internet Explorer",
	Safari: "Safari",
	Edge: "Edge",
	Chrome: "Chrome",
	Firefox: "Firefox Mozilla",
	Mobile: "Mobile",
};
//**************************************************************************************
function BrowserInfo() {
	const res = {
		name: "Unknown",
		version: "0"
	};

	const userAgent = self.navigator.userAgent;

	switch (true) {
		case (/edge\/([\d\.]+)/i.test(userAgent)):
			res.name = Browser.Edge;
			res.version = /edge\/([\d\.]+)/i.exec(userAgent)[1];
			break;
		case (/msie/i.test(userAgent)):
			res.name = Browser.IE;
			res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
			break;
		case (/Trident/i.test(userAgent)):
			res.name = Browser.IE;
			res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
			break;
		case (/chrome/i.test(userAgent)):
			res.name = Browser.Chrome;
			res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
			break;
		case (/mobile/i.test(userAgent) && /firefox/i.test(userAgent)):
		      	res.name = Browser.Mobile;
		      	res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
		      	break;
		case (/mobile/i.test(userAgent)):
			res.name = Browser.Mobile;
			res.version = /mobile\/([\w]+)/i.exec(userAgent)[1];
			break;
		case (/safari/i.test(userAgent)):
			res.name = Browser.Safari;
			res.version = /version\/([\d\.]+)/i.exec(userAgent)[1];
			break;
		case (/firefox/i.test(userAgent)):
			res.name = Browser.Firefox;
			res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
			break;
		default:
			console.log("UNKNOWN BROWSER");
	}

	return res;
}
//**************************************************************************************
function importScripts(src) {
	var script = document.createElement("script");
	script.setAttribute("src", src);

	document.head.appendChild(script);
}
//**************************************************************************************
function linerBrowserInit(path) {
	if (!(self.crypto || self.msCrypto))
		importScripts("//cdnjs.cloudflare.com/ajax/libs/seedrandom/2.4.0/seedrandom.min.js");

	importScripts(path + "webcrypto-liner.shim.min.js")

	switch (BrowserInfo().name) {
		case Browser.IE:
			importScripts(path + "promise.min.js");
		case Browser.Edge:
		case Browser.Safari:
		case Browser.Mobile:
			importScripts(path + "asmcrypto.min.js");
			importScripts(path + "elliptic.min.js");
		default:
	}
}
//**************************************************************************************

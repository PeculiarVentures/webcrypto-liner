//**************************************************************************************
var Browser = {
	IE: "Internet Explorer",
	Safari: "Safari",
	Edge: "Edge",
	Chrome: "Chrome",
	Firefox: "Firefox Mozilla",
};
//**************************************************************************************
function BrowserInfo()
{
	var res = {
		name: "",
		version: ""
	};
	
	var userAgent = self.navigator.userAgent;
	
	switch(true)
	{
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
		case (/safari/i.test(userAgent)):
			res.name = Browser.Safari;
			res.version = /([\d\.]+) safari/i.exec(userAgent)[1];
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
function importScript(src)
{
	var script = document.createElement("script");
	script.setAttribute("src", src);
	
	document.head.appendChild(script);
}
//**************************************************************************************
function linerBrowserInit(path)
{
	if(!(self.crypto || self.msCrypto))
		importScripts("//cdnjs.cloudflare.com/ajax/libs/seedrandom/2.4.0/seedrandom.min.js");

	importScript(path + "webcrypto-liner.shim.min.js")
	
	switch(BrowserInfo().name)
	{
		case Browser.IE:
			importScripts(path + "promise.min.js");
		case Browser.Edge:
		case Browser.Safari:
			importScripts(path + "asmcrypto.min.js");
			importScripts(path + "elliptic.min.js");
		default:
			console.log("UNKNOWN BROWSER, CAN NOT INITIALIZE");
	}
}
//**************************************************************************************

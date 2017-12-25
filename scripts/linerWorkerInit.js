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
function BrowserInfo()
{
	const res = {
		name: "Unknown",
		version: "0"
	};
	
	const userAgent = self.navigator.userAgent;
	
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
function getRandomArbitrary(min, max)
{
	return self.Math.random() * (max - min) + min;
}
//**************************************************************************************
function getRandomValues(buffer)
{
	self.Math.seedrandom(self.location.href, { entropy: true });
	
	const buf = new Uint8Array(buffer.buffer);
	let i = 0;
	
	while(i < buf.length)
		buf[i++] = getRandomArbitrary(0, 255);
	
	return buffer;
}
//**************************************************************************************
export default function linerWorkerInit(path)
{
	const _self = self;
	if(!(_self.crypto || _self.msCrypto))
	{
		importScripts("//cdnjs.cloudflare.com/ajax/libs/seedrandom/2.4.0/seedrandom.min.js");
		_self.crypto = { getRandomValues: getRandomValues };
		Object.freeze(_self.crypto);
	}

	importScripts(path + "webcrypto-liner.lib.min.js");
	
	switch(BrowserInfo().name)
	{
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

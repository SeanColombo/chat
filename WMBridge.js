
// We allow other scripts to re-use this whole system (usually from sibling directories). If they
// have already loaded their config, do not reload it.
var config;
if(typeof module.parent.exports.config != 'undefined'){
	config = module.parent.exports.config;
} else {
	config = require("./server_config.js");
}
var monitoring = require('./monitoring.js');
var qs = require('qs'); 
var storage = require('./storage').redisFactory();
var request = require('request');
var logger = require('./logger').logger;
var url = require('url');
var urlencode = require("./lib/urlencode.js").urlencode;

var requestMW = function(method, roomId, postdata, query, handshake, callback, errorcallback) {
	if(!errorcallback){
		errorcallback = function() {};
	}
	
	if(typeof postdata == "object" && method == 'POST' ) {
		logger.debug(postdata);
		postdata = qs.stringify(postdata);
		logger.debug(postdata);
	} else {
		postdata = "";
	}

	storage.getRoomData(roomId, 'wgServer', function(server) {
		if (server) {
			var wikiHostname = server.replace(/^https?:\/\//i, ''),
				redirectInfo = {
					redirects: 0,   // number of redirects followed so far
					MAX_REDIRECTS: 3,   // maximum number of redirects
					newServer: null   // last redirect host (http(s)://something)
				},
				// settings HTTP headers' variable
				headers = {
					'content-type': 'application/x-www-form-urlencoded'
				};

			if( handshake && handshake.headers ) {
				if( typeof handshake.headers['user-agent'] !== 'undefined' ) {
					headers['user-agent'] = handshake.headers['user-agent'];
				}

				if( typeof handshake.headers['x-forwarded-for'] !== 'undefined' ) {
					headers['x-forwarded-for'] = handshake.headers['x-forwarded-for'];
				}
			}

			/**
			 * check the response and if this is a redirect to a new server, follow it
			 * returns true in case the method handled the redirect response
			 */
			function handleRedirect(response) {
				if (response && (response.statusCode ==  301) && response.headers && response.headers.location) {
					// extract server
					var parts = url.parse(response.headers.location);
					if (parts.hostname != wikiHostname) {
						redirectInfo.redirects++;
						if (redirectInfo.redirects < redirectInfo.MAX_REDIRECTS) {
							redirectInfo.newServer = parts.protocol + '//' + parts.hostname;
							makeRequest(parts.hostname);
							return true;
						}
					}
				}
				return false;
			}

			/**
			 * if we were redirected to a new server, store its address in redis
			 */
			function updateMWaddress() {
				if (redirectInfo.newServer && (server != redirectInfo.newServer)) {
					logger.critical('Old wiki address found: ' + server + ', updating to ' + redirectInfo.newServer);
					storage.setRoomData(roomId, 'wgServer', redirectInfo.newServer);
				}
			}

			/**
			 * Make a request to MW host entrypoint
			 */
			function makeRequest(host) {
				var requestUrl = 'http://' + host + '/index.php' + query + "&cb=" + Math.floor(Math.random()*99999), // varnish appears to be caching this (at least on dev boxes) when we don't want it to... so cachebust it.;
					data;
				logger.debug("Making request to host: " + requestUrl);
				request({
						method: method,
						//followRedirect: false,
						headers: headers,
						body: postdata,
						json: false,
						url: requestUrl
						//proxy: 'http://' + config.WIKIA_PROXY
					},
					function (error, response, body) {
						if (handleRedirect(response)) { // cross-server 301 handling
							return;
						}
						if(error) {
							errorcallback();
							logger.error(error);
							return ;
						}
						logger.debug(response.statusCode);
						if(response.statusCode ==  200) {
							try{
								if((typeof body) == 'string'){
									data = JSON.parse(body);
									logger.debug("parsing");
								} else {
									logger.debug("parsed by request");
									data = body;
								}
								logger.debug(data);
								updateMWaddress();
								callback(data);
							} catch(e) {
								logger.error("Error: while parsing result from:" + requestUrl + '\nError was' + e.message + "\nResponse that didn't parse was:" );
								logger.error(body);
								data = {
									error: '',
									errorWfMsg: 'chat-err-communicating-with-mediawiki',
									errorMsgParams: []
								};
							}
							logger.debug(data);
						}
				});
			}

			makeRequest(wikiHostname);
		}
	},
	errorcallback);
};


var getUrl = function(method, params) {
	var base = "/?action=ajax&rs=ChatAjax&method=" + method + "&";
	
	for(var key in params) {
		base = base + key + "=" + params[key] + "&";
	}
	
	return base;
};

var WMBridge = function() {
//	var BAN_URL = "/?action=ajax&rs=ChatAjax&method=ban";
//	var GIVECHATMOD_URL = "/?action=ajax&rs=ChatAjax&method=giveChatMod";
}


var authenticateUserCache = {};

/**
 * Since there are a variety of encodings for usernames (spaces, underscores, and different
 * encodings of UTF8) it actually turns out to be a lot safer to store the keys by room
 * and clear the cache for an entire room at once. Otherwise, a user with weird-enough
 * UTF8 characters could avoid having their auth info purged from the cache.
 */
var clearAuthenticateCache = function(roomId, name) {
	// We purge the entire room, rather than the specific user because of variations in the way
	// some usernames are URL/UTF8 encoded when they connect vs. when the Admin sends their name
	// to be banned.
	if(authenticateUserCache[roomId]) {
		delete authenticateUserCache[roomId];
	}
}

WMBridge.prototype.authenticateUser = function(roomId, name, key, handshake, success, error) {
	// This cache is only secure because it's checking the .key alongside the roomId/username (roomId
	// and name can be spoofed, but the forger would not also know the 'key' which MediaWiki generates).
	var normalizedName = unescape(name).replace(/ /g, '_');
	if(authenticateUserCache[roomId] && authenticateUserCache[roomId][normalizedName]
		&& (authenticateUserCache[roomId][normalizedName].key == key) ) {
		logger.debug("Used authenticateUserCache to grant acess to: '" + roomId +"' for user '" + normalizedName + "'");
		return success(authenticateUserCache[roomId][normalizedName].data);
	}
	logger.debug("User '" + normalizedName + "' not found in cache for roomId '"+roomId+"'. Server will make auth request to MediaWiki.");

	var requestUrl = getUrl( 'getUserInfo', {
		roomId: roomId,
		name: urlencode(name),
		key: key
	});

	logger.debug(requestUrl);
	var ts = Math.round((new Date()).getTime() / 1000);
	monitoring.incrEventCounter('authenticateUserRequest');
	requestMW( 'GET', roomId, {}, requestUrl, handshake, function(data) {
		if(!authenticateUserCache[roomId]){
			// Initialize cache for room, if needed.
			authenticateUserCache[roomId] = {};
		}
		// Cache entry for this user.
		authenticateUserCache[roomId][normalizedName] = {
			data: data,
			key: key,
			ts: ts
		};
		success(data);
	}, error );
}

// Expire each user's info from the cache after 15 minutes.
setInterval(function() {
	var ts = Math.round((new Date()).getTime() / 1000);
	for (roomId in authenticateUserCache){
		for(name in authenticateUserCache[roomId]){
			if((ts - authenticateUserCache[roomId][name].ts) > 60*15) {
				delete authenticateUserCache[roomId][name];
			}
		}
	}
}, 5000);

WMBridge.prototype.ban = function(client, name, time, reason, success, error) {
	var roomId = client.roomId,
		handshake = client.handshake,
		key = client.userKey,
		userIP = client.handshake.headers['X-Forwarded-For'] || client.request.connection.remoteAddress,
		requestUrl = getUrl('blockOrBanChat', {
		roomId: roomId,
		userToBan: urlencode(name),
		time: urlencode(time),
		reason: urlencode(reason),
		mode: 'global',
		key: key,
		userIP: userIP || ''
	});

	clearAuthenticateCache(roomId, name);

	requestMW('GET', roomId, {}, requestUrl, handshake, function(data){
		// Process response from MediaWiki server and then kick the user from all clients.
		if(data.error || data.errorWfMsg){
			error(data);
		} else {
			success(data);
		}
	});
}


WMBridge.prototype.giveChatMod = function(roomId, name, handshake, key, success, error) {
	clearAuthenticateCache(roomId, name);
	var requestUrl = getUrl('giveChatMod', {
		roomId: roomId,
		userToPromote: urlencode(name),
		key: key,
		userIP: (handshake.address && handshake.address.address) || ''
	});

	requestMW('GET', roomId, {}, requestUrl, handshake, function(data){
		// Process response from MediaWiki server and then kick the user from all clients.
		if(data.error || data.errorWfMsg){
			error(data);
		} else {
			success(data);
		}
	});
};

var setUsersList = function(roomId, users) {
	monitoring.incrEventCounter('broadcastUserList');
	var requestUrl = getUrl('setUsersList', {
		roomId: roomId,
		token: config.TOKEN
	});

	var userToSend = [];

	for(var userName in users) {
		userToSend.push(userName);
	}

	requestMW('POST', roomId, {users: userToSend}, requestUrl, null, function(data){
	});
}

var setUsersListQueue = {};

WMBridge.prototype.setUsersList = function(roomId, users) {
	setUsersListQueue[roomId] = users;
}


setInterval(function() {
	for (i in setUsersListQueue){
		setUsersList(i, setUsersListQueue[i]);
		delete setUsersListQueue[i];
	}
}, 10000);


exports.WMBridge = new WMBridge();

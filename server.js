/** REQUIRES, OTHER SETUP **/
var config = require("./server_config.js");
exports.config = config; // to let submodules know that we've already loaded config.

var app = require('express')()
	, server = require('http').Server(app)
    , io = require('socket.io')(server)
    , jade = require('jade')
    , _ = require('underscore')._
    , Backbone = require('backbone')
    , storage = require('./storage').redisFactory()
    , models = require('./models/models')
// TODO: Refactor this to always call it siteBridge, but to make it so we'll use siteBridge by default and a mwBridge on Wikia (WMbridge is a typo, I think).
    , mwBridge = require('./mwBridge.js').WMBridge // WMBridge was almost certainly a typo.. fix it!
    , loggerModule = require('./logger.js')
    , tracker = require('./tracker.js')
    , monitoring = require('./monitoring.js')
    , logger = loggerModule.logger;

// TODO: Consider using this to catch uncaught exceptions (and then exit anyway):
//process.on('uncaughtException', function (err) {
//  logger.error('Caught exception: ' + err, 'Stacktrace: ', err.stack, 'Full, raw error: ', err);
//	// TODO: is there some way to email us here (if on production) so that we know the server crashed?
//	process.exit(1);
//});

/** DONE WITH LOADING THE CONFIGS & REQUIRES... BELOW IS THE ACTUAL APP CODE! **/

monitoring.startMonitoring(50000, storage);

// This includes and starts the API server (which MediaWiki makes requests to).
logger.critical("== Starting the API Server: instance " + config.INSTANCE + "==");
require("./server_api.js");
monitoring.incrEventCounterUnsampled('server_startup');

// Start the Node Chat server (which browsers connect to).
logger.info("== Starting Node Chat Server ==");
tracker.trackServerStart();
//configure express to use jade
app.set('view engine', 'jade');
app.set('view options', {layout: false});

// configure socket.io
io.set('transports', [  'polling'  ]);
//io.set('authorization', authConnection );
io.use(authConnection);

// NOTE: Testing out these shorter heartbeats to improve disconnections. Default values are 25s and 60s but that doesn't work well.
io.set("heartbeat timeout", 20000);
io.set("heartbeat interval", 10000);

//setup route (just for healthcheck)
app.get('/*', function(req, res){
    res.send('ok');
});

logger.info("== RESTART INFO ==");
logger.info("Next room id: " + storage._get(config.getKey_nextRoomId()));

logger.info("Pruning old room memberships...");
storage.purgeAllMembersFromInstance(config.INSTANCE);

logger.info('Configured to listen on http://' +  config.CHAT_SERVER_HOST + ':' + config.CHAT_SERVER_PORT);
server.listen(config.CHAT_SERVER_PORT, config.CHAT_SERVER_HOST, function () {
	var addr = server.address();
	logger.info('   app listening on http://' + addr.address + ':' + addr.port);
});


logger.info("Updating runtime stats");
storage.getRuntimeStats(function(data) {
	var started = parseInt(new Date().getTime());
	if ( (!data) || isNaN(data.runtime) || isNaN(data.laststart))  {
		data = {
			laststart : started,
			startcount: 0,
			runtime: 0
		};
	} else {
		data.startcount++;
		data.runtime = parseInt(data.runtime) + started - parseInt(data.laststart);
		data.laststart = started;
	}
	logger.debug(data);
	storage.setRuntimeStats(data);
}, null, startServer);

//create local state
var sessionIdsByKey = {}; // for each room/username combo, store the sessionId so that we can send targeted messages.

function startServer() {
	logger.info("Chat server running on port " + config.CHAT_SERVER_PORT);

	storage.resetUserCount();

	// Every time this server gets a connection, it will do this setup for that new client socket.
	io.on('connection', function(clientSocket){

		console.log("connection");
		console.log(clientSocket.handshake);

		if(!clientSocket.handshake || !clientSocket.handshake.clientData) {
			return false;
		}

		// NOTE: Consider using client.handshake.clientData everywhere (in functions that use client) and remove rewrite
		for(var key in clientSocket.handshake.clientData) {
			// ClientData was just being used to smuggle data (such as username, avatarSrc, etc.)
			// from the authConnection. Now that it's here, we can put those keys directly on the
			// object to make them easier to access. This might be less confusing to skip this
			// rewriting here, and just leave it as .handshake.clientData everywhere.
			clientSocket[key] = clientSocket.handshake.clientData[key];
		}
		delete clientSocket.handshake.clientData; // clean up a small bit of memory.

		monitoring.incrEventCounter('connects');
		storage.increaseUserCount(1);

		// On initial connection, just wait around for the client to send it's authentication info.
		clientSocket.on('message', function(msg){
			messageDispatcher(clientSocket, io.sockets, msg);}
		);

		clientSocket.on('disconnect', function(){
			monitoring.incrEventCounter('disconnects');
			storage.increaseUserCount(-1);
			clientDisconnect(clientSocket, io.sockets);
		});

		// Why? Seems only for readability. Kinda weird (even though it's probably never going
		// to be overwritten, it's duplicate state which can be dangerous if you ever write to it).
		clientSocket.sessionId = clientSocket.id;

		clearChatBuffer(clientSocket);

		logger.debug("Raw connection received. Waiting for authentication info from client.");
	});
}

/**
 * Bound to the 'message' event, gets any message from the client. If the user
 * is not authenticated, this won't listen to anything other than authentications.
 */
function messageDispatcher(client, ioSockets, data){
	// The user is authed. Check to make sure their client sessionId still exists. If it doesn't, we probably banned them.
	var sessionId = false;
	if(typeof client.myUser != 'undefined' && typeof client.myUser.get != 'undefined'){
		sessionId = sessionIdsByKey[config.getKey_userInRoom(client.myUser.get('name'), client.roomId)];
	}
	if(sessionId === false || (typeof sessionId == "undefined") || (sessionId != client.sessionId)){
		client.json.send({
				event: 'forceReconnect'
		});
		// Message ignored. Log the reason.
		if(sessionId === false || typeof sessionId == "undefined"){
				logger.debug("GOT A MESSAGE WITH NO socket.io sessionId. ASSUMING THEY ARE BANNED AND SKIPPING.");
		} else if(sessionId != client.sessionId){
				var msg = "Got a message from a user with a mismatched client-id. This implies that the user sending the message ";
				msg += "(" + client.myUser.get('name');
				msg += ") has connected from a newer browser and the old browser which sent the message has been closed ";
				msg += "and is in the process of having its connection closed.";
				logger.debug(msg);
		}
	} else {
		// The user is authenticated.  Dispatch to appropriate place for the message.
		var dataObj;
		try{
			dataObj = JSON.parse(data);
		} catch(e){
			logger.error("Error: while parsing raw incoming json (to msg dispatcher). Error was: ", e, "JSON-string that didn't parse was:\n" + data);
			return true;
		}
		if(!dataObj) {
			logger.error("Error: Null object while parsing incoming json. JSON-string that didn't parse was:\n" + data);
			return true;
		}
		if(typeof dataObj.attrs == 'undefined'){
			dataObj.attrs = {};
		}
		if(typeof dataObj.attrs.msgType == 'undefined'){
			dataObj.attrs.msgType = "[msgType was undefined]";
		}

		switch(dataObj.attrs.msgType){
			case 'chat':
				logger.debug("Dispatching to message handler.");
				chatMessage(client, ioSockets, data);
				client.msgCount++;
				break;
			case 'command':
				switch(dataObj.attrs.command){ // all commands should be in lowercase
					case 'initquery':
						sendRoomDataToClient(client);
						break;
					case 'logout':
						logger.debug("Loging out user: " + client.myUser.get('name'));
						logout(client, ioSockets, data);
						break;
					case 'kick':
						logger.info("Kicking user: " + dataObj.attrs.userToKick);
						kick(client, ioSockets, data);
						break;
					case 'ban':
						logger.info("Banning user: " + dataObj.attrs.userToBan);
						ban(client, ioSockets, data);
						break;
					case 'openprivate':
						logger.debug( "openPrivateRoom" );
						openPrivateRoom(client, ioSockets, data);
						break;
					case 'givechatmod':
						logger.info("Giving chatmoderator status to user: " + dataObj.attrs.userToPromote);
						giveChatMod(client, ioSockets, data);
						break;
					case 'setstatus':
						logger.debug("Setting status for " + client.myUser.get('name') + " to " + dataObj.attrs.statusState + " with message '" + dataObj.attrs.statusMessage + "'.");
						setStatus(client, ioSockets, data);
						break;
					default:
						logger.warning("Unrecognized command: " + dataObj.attrs.command);
					break;
				}
				break;
			default:
				logger.error("ERROR: Could not find recognized msgType to handle data: ", data);
				break;
		}
	}
} // end messageDispatcher()


/**
 *  open private chat with other users
 */

function openPrivateRoom(client, ioSockets, data){
	var roomInfo = new models.OpenPrivateRoom();
	roomInfo.mport(data);

	storage.getUsersAllowedInPrivateRoom(roomInfo.get('roomId'), function(users) {
		var privateRoom = new models.OpenPrivateRoom( { roomId : roomInfo.get('roomId'), users: users } );
		broadcastToRoom(client, ioSockets, {
			event: 'openPrivateRoom',
			data: privateRoom.xport()
		}, users);
	});
}

/**
 * After the initial connection, the client will be expected to send its auth
 * info (essentially: the Wikia authentication cookies) so that we can then
 * use this info to verify with the Wikia apaches that the user is connected
 * and what their rights are.
 *
 * The authData should also contain two keys: 'cookie' and 'roomId', the roomId
 * of the room the user is trying to enter (must be on the wiki which they are
 * chatting on - this guarantees that the permissions checks for the room's wiki
 * are used - since users could be banned on one wiki and not another).
 */
function authConnection(socket, next){
	logger.debug("Authentication info recieved from client. Verifying with Wikia MediaWiki app server...");
	// Need to auth with the correct wiki. Lookup the hostname for the chat in redis.
	handshakeData = socket.handshake;

	console.log(socket.handshake);
	if(!handshakeData.query.roomId || !handshakeData.query.name || !handshakeData.query.key) {
		logger.warning("Wrong handshake data");
		next(new Error('Wrong handshake data'));
		//authcallback(null, false); // error first callback style
		return false;
	}

	var roomId = handshakeData.query.roomId;
	var name = handshakeData.query.name;
	var key = handshakeData.query.key;

	var callback = function(data) {

		var usernameOk = (data.username_encoded == name) || (unescape(data.username) == unescape(name))
		logger.debug("auth test: " + data.username_encoded + "==" + data.username + "==" + unescape(data.username) + "==" + name);

		if(data.canChat && data.isLoggedIn && usernameOk){
			var errback = function() {
				logger.info("User tried to connect with someone elses private room");
				next(new Error('User tried to connect with someone elses private room'));

				//authcallback(null, false); // error first callback style
				//it is hack attempts no meesage for this
			};

			storage.getUsersAllowedInPrivateRoom(roomId, function(users) {
				if(users.length == 0 || _.indexOf(users, data.username) !== -1 ) { //
					var clientData = {};
					clientData.userKey = key;
					clientData.msgCount = 0;
					clientData.username = data.username;
					clientData.avatarSrc = data.avatarSrc;
					clientData.isChatMod = data.isChatMod;
					clientData.editCount = data.editCount;
					clientData.wikiaSince = data.since;
					clientData.isCanGiveChatMod = data.isCanGiveChatMod;
					clientData.isStaff = data.isStaff;
					clientData.roomId = roomId;
					clientData.cityId = data.wgCityId;
					clientData.privateRoom = !(users.length == 0);
					// TODO: REFACTOR THIS TO TAKE ANY FIELDS THAT data GIVES IT.
					clientData.ATTEMPTED_NAME = data.username;
					// User has been approved & their data has been set on the client. Put them into the chat.
					clientData.wgServer = data.wgServer;
					clientData.wgArticlePath = data.wgArticlePath;

					// We need to smuggle this data to the 'connection' callback in a new
					// key called "clientData". Then clientData will then be unpacked onto
					// the clientSocket itself.
					handshakeData.clientData = clientData;
					logger.debug("User authentication success.");
					monitoring.incrEventCounter('logins');
					next();
					//authcallback(null, true); // error first callback style
				} else {
					errback();
				}
			}, errback);
		} else {
			logger.error("User failed authentication. Error from server was: " + data.errorMsg);
//			sendInlineAlertToClient(client, data.error, data.errorWfMsg, data.errorMsgParams);
			logger.debug("Entire data was: ");
			logger.debug(data);
			next(new Error('User failed authentication (1)'));
			//authcallback(null, false); // error first callback style
		}
	};

	mwBridge.authenticateUser(roomId, name, key, handshakeData, callback, function(){
		logger.error("User failed authentication: Wrong call to media wiki");
		//authcallback(null, false); // error first callback style
		next(new Error('User failed authentication (2)'));
	});
} // end of socket connection code

function clearChatBuffer(client) {
	// TODO: REFACTOR THESE TO USE THE VALUE STORED IN THE 'chat' OBJ IN REDIS (remove the setting of these client vars from the ajax request also).

	// BugzId 5752 - clear chat buffer if this is the first user in the room (to avoid confusion w/past chats).
	storage.countUsersInRoom(client.roomId, function(numInRoom) {
		if((numInRoom) && (numInRoom > 0)){
			finishConnectingUser(client, io.sockets );
		} else {
			// Nobody is in the room yet, so clear the back-buffer before doing the rest of the setup (as per BugzId 5752).
			logger.debug(client.username + " is the first person to re-enter a now-empty room " + client.roomId + ".");
			logger.debug("Deleting the back-buffer before connecting them the rest of the way.");

			storage.deleteChatRoomEntries(client.roomId, null, null, function() {
				finishConnectingUser( client, io.sockets );
			});
		}
	});
}


function sendRoomDataToClient(client) {
        storage.getRoomState(client.roomId, function(nodeChatModel) {
                // this is called after getUsersInRoom callback
                // Send this whole model to the newly-connected user.
                logger.debug("SENDING INITIAL STATE...");
                logger.debug(nodeChatModel.xport());
                client.json.send({
                        event: 'initial',
                        data: nodeChatModel.xport()
                });
	});
}

/**
 * This is called after the result from the MediaWiki server has set up this client's user-info.
 * This adds the user to the room in redis and sends the initial state to the client.
 */
function finishConnectingUser(client, ioSockets ){
	logger.debug( 'finishConnectingUser:' + (new Date().getTime()));

	storage.getRoomState(client.roomId, function(nodeChatModel) {
		// Initial connection of the user (unless they're already connected).
		var connectedUser = nodeChatModel.users.findByName(client.username);
		newConnectedUser = new models.User({
			name: client.username,
			avatarSrc: client.avatarSrc,
			isModerator: client.isChatMod,
			isCanGiveChatMod: client.isCanGiveChatMod,
			isStaff: client.isStaff,
			editCount: client.editCount,
			since: client.wikiaSince
		});

		if(connectedUser) {
			nodeChatModel.users.remove(connectedUser);
		}

		nodeChatModel.users.add(newConnectedUser);
		connectedUser = newConnectedUser;
		logger.debug('[getConnectedUser] new user: ' + connectedUser.get('name') + ' on client: ' + client.sessionId);
		client.myUser = newConnectedUser;

		if( client.ATTEMPTED_NAME != client.myUser.get('name') ){
			logger.warning("\t\t============== POSSIBLE IDENTITY PROBLEM!!!!!! - BEG ==============");
			logger.warning("\t\tATTEMPTED NAME:     " + client.ATTEMPTED_NAME + " (probably the correct name)");
			logger.warning("\t\tATTACHED TO USR:    " + client.myUser.get('name'));
			logger.warning("\t\t============== POSSIBLE IDENTITY PROBLEM!!!!!! - END ==============");
		}

		// If this same user is already in the sessionIdsByKey hash, then they must be connected in
		// another browser. Kick that other instance before continuing (multiple instances cause all kinds of weirdness).
		var existingId = sessionIdsByKey[config.getKey_userInRoom(client.myUser.get('name'), client.roomId)];

		logger.debug("existingId: " + existingId );

		var oldClient = existingId != "undefined" ? ioSockets.connected[existingId] : false;

		if(oldClient && oldClient.userKey != client.userKey ){
			logger.debug("oldClient key:" + oldClient.userKey);

			oldClient.donotSendPart = true;
			if(!oldClient.logout) {
				tracker.trackEvent(client, 'disconnect');
			}
			// Send the old client a notice that they're about to be disconnected and why.
			sendInlineAlertToClient(oldClient, '', 'chat-err-connected-from-another-browser', [], function(){
				// Looks like we're kicking ourself, but since we're not in the sessionIdsByKey map yet,
				// this will only kick the other instance of this same user connected to the room.
				logger.debug('kickUserFromRoom');
					kickUserFromRoom(oldClient, ioSockets, client.myUser, client.roomId, function(){
					logger.debug('kickUserFromRoom call back');
					// This needs to be done after the user is removed from the room.  Since clientDisconnect() is called asynchronously,
					// the user is explicitly removed from the room first, then clientDisconnect() is prevented from attempting to remove
					// the user (since that may get called at some point after formallyAddClient() adds the user intentionally).
					formallyAddClient(client, ioSockets, connectedUser);
				});
			});
		} else {
			//we have double connection for the same window
			if(oldClient){
				monitoring.incrEventCounter('double_connects');
				tracker.trackEvent(client, 'disconnect');
				oldClient.donotSendPart = true;
                                setTimeout(function(){
                                        if(oldClient){
                                                oldClient.disconnect();
                                        }
                                }, 1000 * 30);
			}
			// Put the user info into the room hash in redis, and add the client to the in-memory (not redis) hash of connected sockets.
			formallyAddClient(client, ioSockets, connectedUser);
		}
	});
} // end finishConnectingUser()

/**
 * Adds the client to their room in redis and adds their sessionId to the hash of sessionIdsByKey.
 *
 * This should only be done after any duplicates of this user have been ejected from the room already (in the case
 * of the same user connecting from multiple browsers).
 */
function formallyAddClient(client, ioSockets, connectedUser){
	// Add the user to the set of users in the room in redis.
	var userData = client.myUser.attributes;
	delete userData.id;
	logger.debug("clientConencted");
	tracker.trackEvent(client, 'connect');
	sessionIdsByKey[config.getKey_userInRoom(client.myUser.get('name'), client.roomId)] = client.sessionId;
	storage.setUserData(client.roomId, client.myUser.get('name'), userData,
		null,
		null,
		function() {	// in original code it was done it both cases (success and error) so I do it the same way
			// Broadcast the join to all clients.
			logger.debug(new Date().getTime());
			broadcastToRoom(client, ioSockets, {
				event: 'join',
				data: connectedUser.xport()
			});
			broadcastUserListToMediaWiki(client, false);
			//Conenction complted
		}
	);
} // end formallyAddClient()

/**
 * Called when a client disconnects from the server.
 *
 * If client has property 'doNotRemoveFromRedis' set to true, then the user will not be removed from the room hash
 * in redis (this is used sometimes to prevent race conditions).
 */
function clientDisconnect(client, ioSockets) {
	logger.debug("clientDisconnect");
	// Remove the in-memory mapping of this user in this room to their sessionId
	if(typeof client.myUser != 'undefined' && typeof client.myUser.get != 'undefined'){
		if(sessionIdsByKey[config.getKey_userInRoom(client.myUser.get('name'), client.roomId)] == client.sessionId ) {
			delete sessionIdsByKey[config.getKey_userInRoom(client.myUser.get('name'), client.roomId)];
		} else {
			return true;
		}
	}

	// Remove the user from the set of usernames in the current room (in redis).
	if(client.doNotRemoveFromRedis){
//		logger.debug("Not removing user from room, just broadcasting their part & the associated inline alert for " + client.myUser.get('name'));
		broadcastDisconnectionInfo(client, ioSockets);
	} else if(typeof client.myUser != 'undefined' && typeof client.myUser.get != 'undefined'){
		logger.debug("Disconnected: " + client.myUser.get('name') + " and about to remove them from the room in redis & broadcast the part and InlineAlert...");
		storage.removeUserData(client.roomId, client.myUser.get('name'), function(data) {
			broadcastDisconnectionInfo(client, ioSockets);
		});
	}
} // end clientDisconnect()

/**
 * After a client has been disconnected, broadcast the part and the associated inline-alert to all remaining members of the room.
 */
function broadcastDisconnectionInfo(client, ioSockets){
	// Delay before sending part messages because there are occasional disconnects/reconnects or just ppl refreshing their browser
	// and that's really not useful information to anyone that under-the-hood they were disconnected for a moment (BugzId 5753).

	if(client.donotSendPart) {
		return true;
	}

	tracker.trackEvent(client, 'disconnect');

	broadcastUserListToMediaWiki(client, true);

	var partEvent = new models.PartEvent({
		name: client.myUser.get('name')
	});
	broadcastToRoom(client, ioSockets, {
        	event: 'part',
        	data: partEvent.xport()
	});
} // end broadcastDisconnectionInfo()

/**
 * Given a roomId, returns a list of the usernames of all users in the room (as JSON).
 */
function broadcastUserListToMediaWiki(client, removeClient){
	if(client.donotBroadcastUserList) {
                return true;
        }

	storage.getUsersInRoom(client.roomId, function(users) {
		if(!users){users = {};} // if the key doesn't exist, return an empty userlist
		if(removeClient) {
			for( var i in users ) {
				if(i == client.username) {
					delete users[i];
				}
			}
		}
		logger.debug("Sending status update to media wiki")
		if(!client.privateRoom) {
			mwBridge.setUsersList(client.roomId, users);
		}
	});
} // end api_getUsersInRoom()


/** MESSAGE HANDLERS **/

/**
 * Processes a message sent by a client (and broadcasts it out to all users in the same room).
 */
function chatMessage(client, ioSockets, msg){
	var chatEntry = new models.ChatEntry();
    chatEntry.mport(msg);
	// messages sent from client cannot be inline, as those messages are not escaped
	// InlineAlert messages can be broadcasted only by the server
	if (chatEntry.get('isInlineAlert')) {
		var logMsg = 'Possible XSS attempt from user ' + client.myUser.get('name');
		if (client.handshake.address && client.handshake.address.address) {
			logMsg += '/' + client.handshake.address.address;
		}
		logMsg += ': ' + JSON.stringify(chatEntry);
		logger.critical(logMsg);
		return;
	}
	var text = chatEntry.get('text');
	if (typeof(text) !== "string" || text.length === 0) {
		// skip empty messages
		return;
	}
	//chatEntry.set({ isInlineAlert: false}); // not needed, as we ingore those messages
    monitoring.incrEventCounter('chat_messages');
	storeAndBroadcastChatEntry(client, ioSockets, chatEntry);
} // end chatMessage()

function logout(client, ioSockets, msg) {
	var logoutEvent = new models.LogoutEvent({
		name: client.myUser.get('name')
	});
	monitoring.incrEventCounter('logouts');
	tracker.trackEvent(client, 'logout');
	client.logout = true;
	// I'm still not sure if we should call kickUserFromRoom here or not...
	broadcastToRoom(client, ioSockets, {
			event: 'logout',
			data: logoutEvent.xport()
		},
		null,
		function() {
			client.donotSendPart = true;
			broadcastUserListToMediaWiki(client, true);
		}
	);
}

/**
 * Kicks the specified user, then broadcasts the effects to other users.
 */
function kick(client, ioSockets, msg){
	var kickCommand = new models.KickCommand();
    kickCommand.mport(msg);

	var userToKick = kickCommand.get('userToKick');
	storage.getRoomState(client.roomId, function(nodeChatModel) {
		var kickedUser = nodeChatModel.users.findByName(userToKick);
		if (typeof kickedUser !== "undefined") {
			if ( client.myUser.get('isModerator') !== true) {
				sendInlineAlertToClient(client, '', 'chat-kick-you-need-permission', []);
			} else if ( kickedUser.get('isCanGiveChatMod') || ( kickedUser.get('isModerator') === true && client.myUser.get('isCanGiveChatMod') !== true ) ) {
				sendInlineAlertToClient(client, '', 'chat-kick-cant-kick-moderator', []);
			} else {
				var kickEvent = new models.KickEvent({
					kickedUserName: kickedUser.get('name'),
					moderatorName: client.myUser.get('name')
				});
				broadcastToRoom(client, ioSockets, {
						event: 'kick',
						data: kickEvent.xport()
					},
					null,
					function() {
						client.donotSendPart = true;
						kickUserFromRoom(client, ioSockets, kickedUser, client.roomId);
					}
				);
			}
		}
	});

} // end kick()

/**
 * Kicks and bans the specified user, then broadcasts the effects to other users.
 */
function ban(client, ioSockets, msg){
	var banCommand = new models.BanCommand();
    banCommand.mport(msg);

	var userToBan = banCommand.get('userToBan');
	var userToBanObj = new models.User({name: userToBan});
	var time = banCommand.get('time');
	var reason = banCommand.get('reason');

	mwBridge.ban(client, userToBan, time, reason, function(data){
    	var kickEvent = new models.KickEvent({
    		kickedUserName: userToBan,
    		time: time,
    		moderatorName: client.myUser.get('name'),
    		reason: reason
    	});

    	broadcastToRoom(client, ioSockets, {
			event: 'ban',
			data: kickEvent.xport()
		},
		null,
		function() {
			client.donotSendPart = true;
			kickUserFromRoom(client, ioSockets, userToBanObj, client.roomId);
		});

	}, function(data){
		sendInlineAlertToClient(client, data.error, data.errorWfMsg, data.errorMsgParams);
	});
} // end ban()

/**
 * Add the chatmoderator group to the user whose username is specified in the command (if allowed).
 */
function giveChatMod(client, ioSockets, msg){
	var giveChatModCommand = new models.GiveChatModCommand();
	giveChatModCommand.mport(msg);

	var userNameToPromote = giveChatModCommand.get('userToPromote');

	mwBridge.giveChatMod(client.roomId, userNameToPromote, client.handshake, client.userKey, function(data){
		// Build a user that looks like the one that got banned... then kick them!

		storage.getRoomState(client.roomId, function(nodeChatModel) {
			// Initial connection of the user (unless they're already connected).
			var promotedUser = nodeChatModel.users.findByName(userNameToPromote);

			if(!promotedUser) {
				return true;
			}

			promotedUser.set('isModerator', true);

			broadcastInlineAlert(client, ioSockets, 'chat-inlinealert-a-made-b-chatmod', [client.myUser.get('name'), promotedUser.get('name')], function() {
				storage.setUserData(client.roomId, promotedUser.get('name'), promotedUser.attributes, null, null, function() {
					// Broadcast the user as an update to everyone in the room
					broadcastToRoom(client, ioSockets, {
						event: 'updateUser',
						data: promotedUser.xport()
					});
				});
			});
		});
	},function(data){
		sendInlineAlertToClient(client, data.error, data.errorWfMsg, data.errorMsgParams);
	});
} // end giveChatMod()

/**
 * Given a User model and a room id, disconnect the client if that username has a client connected. Also,
 * remove them from the room hash in redis.
 */
function kickUserFromRoom(client, ioSockets, userToKick, roomId, callback){
	// Removing the user from the room.
	logger.debug("Kicking " + userToKick.get('name') + " from room " + roomId);
	storage.removeUserData(roomId, userToKick.get('name'), function() {
		kickUserFromServer(client, ioSockets, userToKick, roomId);

		if(typeof callback == "function"){
			callback();
		}
	});
} // end kickUserFromRoom()

/**
 * Given a User model and a room id, disconnect the client if that username has a client connected.
 * This only closes their connection, but does not delete their entry from the room in redis. If you
 * want to remove the user from the room also, use kickUserFromRoom() instead.
 */
function kickUserFromServer(client, ioSockets, userToKick, roomId){
	// Force-close the kicked user's connection so that they can't interact anymore.
	logger.debug("Force-closing connection for kicked user: " + userToKick.get('name'));
	var kickedClientId = sessionIdsByKey[config.getKey_userInRoom(userToKick.get('name'), roomId)];

	if(typeof kickedClientId != 'undefined'){
		// If we're kicking the user (for whatever reason) they shouldn't try to auto-reconnect.
		ioSockets.connected[kickedClientId].json.send({
			event: 'disableReconnect'
		});

		// To prevent race-conditions, we don't have any users kicked by this function get removed from
		// redis. Setting this variable here lets clientDisconnect() know not to delete the user from the
		// room in redis.
		setTimeout(function(){
			if (ioSockets.connected[kickedClientId]) {
				ioSockets.connected[kickedClientId].doNotRemoveFromRedis = true;
				ioSockets.connected[kickedClientId].disconnect();

			}
		}, 1000);
		// This closes the connection (takes a few seconds) after calling the clientDisconnect() handler which will
		// broadcast the 'part' and delete the session id from the sessionIdsByKey hash.

		//clientDisconnect(ioSockets.socket(kickedClientId), ioSockets);
		// NOTE: This is the way fzysqr does it (as opposed to the ._onDisconnect() done above).  It might close the connection more quickly (the _onDisconnect() works and is tested but the client stays open for a few seconds).
		//ioSockets.clients[kickedClientId].send({ event: 'disconnect' });
		//ioSockets.clients[kickedClientId].connection.end();
	}
} // end kickUserFromServer()

/**
 * Sets the current user's status and broadcasts it out to the other users in the same room.
 */
function setStatus(client, ioSockets, setStatusData){

	logger.debug("SetStatusCommand", setStatusData);
	logger.debug("SetStatusCommand1");
	var setStatusCommand = new models.SetStatusCommand();
	logger.debug("SetStatusCommand2");

    setStatusCommand.mport(setStatusData);

	var userName = client.myUser.get('name');
	var roomId = client.roomId;

	storage.getUserData(roomId, userName, function(userData) {
		if(userData){
			// Modify the user's status and store them back in the hash
			userData.statusState = setStatusCommand.get('statusState');
			userData.statusMessage = setStatusCommand.get('statusMessage');
			storage.setUserData(roomId, userName, userData, null, null, function() {
				// Broadcast the user as an update to everyone in the room
				var userToUpdate = new models.User( userData );
				broadcastToRoom(client, ioSockets, {
					event: 'updateUser',
					data: userToUpdate.xport()
				});
			});
		} else {
			logger.warning("Attempted to set status for user '" + userName + "', but that user was not found in room '" + roomId + "'");
		}
	});
} // end setStatus()



/** HELPER FUNCTIONS **/

/**
 * Sends some text to the client specified as an InlineAlert but does not store it
 * or persist it anywhere.
 *
 * Can use client-side i18n, so expects EITHER a 'text' string or a MediaWiki message name and parameters (pass in an
 * empty string for 'text' parameter if using client-side i18n).
 */
function sendInlineAlertToClient(client, text, wfMsg, msgParams, callback){
	var inlineAlert = new models.InlineAlert({
		text: text,
		wfMsg: wfMsg,
		msgParams: msgParams
	});
	client.json.send({
		event: 'chat:add',
		data: inlineAlert.xport()
	});
	if(typeof callback == "function"){
		callback();
	}
} // end sendInlineAlertToClient()

/**
 * Given some text, adds the InlineAlert to the model and broadcasts it out to the other clients in the room.
 *
 * NOTE: Not using this for join/part/banned anymore because of https://wikia.fogbugz.com/default.asp?4766
 * Those messages are now transient/ephemeral and are just sent with broadcastInlineAlert
 */
function storeAndBroadcastInlineAlert(client, ioSockets, text, callback){
	var inlineAlert = new models.InlineAlert({text: text});
	storeAndBroadcastChatEntry(client, ioSockets, inlineAlert, callback);
} // end storeAndBroadcastInlineAlert()

/**
 * Given a ChatEntry (which might be of the InlineAlert subclass), store it to the model and
 * broadcast it to all of the clients in the room.
 */
function storeAndBroadcastChatEntry(client, ioSockets, chatEntry, callback){
	storage.getNextChatEntryId(function(newId) {
		// The user sends their username along with the chat entry. Here we can verify that this matches
		// the username on the socket. This will help us detect when sessions get garbled.
		if(chatEntry.get('name') != client.myUser.get('name')){
			// Normally, we trust the client.myUser (it's attached to the socket) but if they mismatch, if that wasn't
			// done intentionally by an attacker, then we likely had the session-swapping bug. Our current hypothesis is
			// that the bug is caused by thousands of users trying to reconnect simultaneously.
			logger.critical("-- SOCKETSWAPPING-3 -- Got a message from user '" +chatEntry.get('name') + "' through socket for '" + client.myUser.get('name') +"'");
			
			// The user's sockets got confused in socket.io... have the user re-connect.
			client.json.send({
				event: 'forceReconnect'
			});
		} else {
			// Set the id from redis, and the name/avatar based on what we KNOW this client's credentials to be.
			// Originally, the client may spoof a name/avatar, but we will ignore what they gave us and override them here.
			var now = new Date();
			chatEntry.set({
				id: newId,
				name: client.myUser.get('name'),
				avatarSrc: client.myUser.get('avatarSrc'),
				text: chatEntry.get('text'),
				timeStamp: now.getTime()
			});

			var expandedMsg = chatEntry.get('id') + ' ' + chatEntry.get('name') + ': ' + chatEntry.get('text');
			logger.debug('(' + client.sessionId + ':' + chatEntry.get('name') + ') ' + expandedMsg);

			storage.addChatEntry(client.roomId, chatEntry.xport(), null, null, function() {
				// Send to everyone in the room.
				broadcastChatEntryToRoom(client, ioSockets, chatEntry, callback);
			});
		}
	});
} // end chatMessage()

/**
 * For broadcasting text (as an ephemeral - not persisted - InlineAlert) to all
 * members of the same room that client is in.
 *
 * @param wfMsg - the MediaWiki message name (will be translated client-side).
 * @param msgParams - an array containing the parameters (if any) to be passed in with the i18n message to $.msg().
 */
function broadcastInlineAlert(client, ioSockets, wfMsg, msgParams, callback){
	var inlineAlert = new models.InlineAlert({
		text: '',
		wfMsg: wfMsg,
		msgParams: msgParams
	});
	broadcastChatEntryToRoom(client, ioSockets, inlineAlert, callback);
} // end broadcastInlineAlert()

/**
 * Send the 'chat:add' update to all clients in the chat room.  This assumes that the caller
 * has already added the chatEntry to the model if it wants the chatEntry to be in the model.
 */
function broadcastChatEntryToRoom(client, ioSockets, chatEntry, callback){
	broadcastToRoom(client, ioSockets, {
		event: 'chat:add',
		data:chatEntry.xport()
	},[], callback);
} // end broadcastChatEntryToRoom()

/**
 * Broadcasts the 'data' to all of the clients who are in the room specified
 * by 'roomId'.
 *
 * 'callback' is optional, if defined it will be called after the broadcasting is complete.
 */

function broadcastToRoom(client, ioSockets, data, users, callback){
	var roomId = client.roomId;
	// Get the set of members from redis.
	logger.debug("Broadcasting to room " + roomId);
	storage.getUsersInRoom(roomId, function(usernameToUser) {
		logger.debug("Raw data from key " + config.getKey_usersInRoom( roomId ) + ": ", "usernameToUser:", usernameToUser);

		var usernameToUserFiltered = {};

		// users is only non-empty if we are sending to a private room (filtered list)
		if((users instanceof Array) && users.length > 0) {
			for( var i in users ) {
				if(usernameToUser && typeof(usernameToUser[users[i]]) != 'undefined') {
					usernameToUserFiltered[users[i]] = usernameToUser[users[i]];
				}
			}
		} else {
			usernameToUserFiltered = usernameToUser;
		}

		//logger.debug(usernameToDataFiltered);
		_.each(usernameToUserFiltered, function(userModel){
			logger.debug("\tSENDING TO " + userModel.get('name'));
			var socketId = sessionIdsByKey[ config.getKey_userInRoom(userModel.get('name'), roomId) ];

			if(socketId){
				//logger.debug("============ SOCKET "+socketId+" ==========================================");
				//logger.debug(ioSockets.socket(socketId));
				//logger.debug("============ /SOCKET "+socketId+" ==========================================");

				if( typeof ioSockets.connected[socketId].sessionId  == "undefined"){
					// This happened once (and before this check was here, crashed the server).  Not sure if this is just a normal side-effect of the concurrency or is a legit
					// problem. This logging should help in debugging if this becomes an issue.
					logger.warning("Somehow the client socket for " + userModel.get('name') + " is totally closed but their socketId is still in the hash. Potentially a race-condition?");
					delete sessionIdsByKey[ config.getKey_userInRoom(userModel.get('name'), roomId) ];
				} else {
					// SWC 20150303 - just noticed this method has been using the global io.sockets instead of the
					// local ioSockets var. That's probably fairly equivalent at the moment... but we should def. use
					// the local var if it is going to exist at all.
					//io.sockets.connected[socketId].json.send(data);
					ioSockets.connected[socketId].json.send(data);
				}
			}
		});

		if(typeof callback == "function"){
			callback();
		}
	});
} // end broadcastToRoom()

/**
 * Helper-function to log the details of a more complex object.
 */
function debugObject(obj, padding){
	if (!logger.isDebug()) return;

	if(!padding){padding = '';}

	if(typeof(obj) == 'object'){
		logger.debug(padding + "OBJECT: ");
		for(var index in obj){
			//if(obj.hasOwnProperty(index)){
				var item = obj[index];
				if(typeof(item) == 'object'){
					debugObject(item, "   "); // recursively show the sub-item (indented a bit)
				} else {
					logger.debug(padding + "   " + index + ": " + item);
				}
			//}
		}
	} else {
		logger.debug(padding + "Not an object: " + obj);
	}
}

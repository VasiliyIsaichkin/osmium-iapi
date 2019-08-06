const {WebApiServer, WebApiClient} = require('osmium-webapi');
const {Crypt, tools} = require('osmium-crypt');

class IApiServer extends WebApiServer {
	constructor(io, options, name, authProvider) {
		options.isServer = true;
		options.clientProcessor = (socket) => new IApiClient(socket, options, name, authProvider);
		super(io, options);
	}
}

class IApiClient extends WebApiClient {
	constructor(socket, options, name, authProvider) {
		Object.assign(options, {
			keySalt      : 'sZGtr3YzPxQlG57ZqFxpIS45stYly9BC',
			prefix       : 'iApi',
			nameReqCmd   : 'n',
			nameReqCmdRet: 'r'
		});
		super(socket, options);
		this.options.iApiVersion = 4;

		this.cryptor = new Crypt(this.options);
		this.remoteName = false;

		socket.on(`${this.options.prefix}${this.options.nameReqCmd}`, () => {
			socket.emit(`${this.options.prefix}${this.options.nameReqCmdRet}`, name);
		});

		this.registerMiddlewareOut(async (packet) => {
			await this.requestRemoteName(socket);
			
			const id = packet.id;
			delete packet.id;
			const sharedKey = authProvider.get(this.options.isServer, this.remoteName, name, this.options.keySalt);
			const payload = await this.cryptor.encrypt(sharedKey, packet, id + '|' + socket.id,
				{v: this.options.iApiVersion, i: name});

			return {
				version : packet.version,
				id,
				name,
				args    : payload,
				metadata: packet.metadata
			};
		});

		this.registerMiddlewareInc(async (packet) => {
			await this.requestRemoteName(socket);

			const sharedKey = authProvider.get(this.options.isServer, this.remoteName, name, this.options.keySalt,
				(userData) => userData.v === this.options.iApiVersion && userData.i === this.remoteName);
			const data = await this.cryptor.decrypt(sharedKey, packet.args, true);
			if (!data || !data.id) return null;
			packet = data.payload;
			const idArr = data.id.split('|');
			if (idArr[1] !== socket.id) return null;
			packet.id = idArr[0];
			return packet;
		});
	}

	async requestRemoteName(socket) {
		if (this.remoteName) return;
		this.remoteName = await new Promise((resolve) => {
			const cmd = `${this.options.prefix}${this.options.nameReqCmd}`;
			const iId = setInterval(() => socket.emit(cmd), 1000);
			socket.once(`${this.options.prefix}${this.options.nameReqCmdRet}`, (p) => {
				clearInterval(iId);
				resolve(p);
			});
			socket.emit(cmd);
		});
	}
}

module.exports = {
	IApiServer,
	IApiClient
};

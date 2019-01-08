const {WebApiServer, WebApiClient} = require('osmium-webapi');
const {Crypt} = require('osmium-crypt');

class IApiSimpleAuthProvider {
	constructor(jsonAuthList) {
		this.list = jsonAuthList;
	}

	get(name, remoteIdx, fn) {
		return (userData) => {
			if (!name && (!userData || !userData[remoteIdx])) return '';
			if (fn) if (!fn(userData)) return '';
			return '' + (name ? this.list[name] : this.list[userData[remoteIdx]]);
		};
	}
}

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
			keySalt      : 'XzNfq@UYplXiFOdoM0S*vxBC~b#*r0~z',
			prefix       : 'iApi',
			nameReqCmd   : 'n',
			nameReqCmdRet: 'r'
		});
		super(socket, options);
		this.options.iApiVersion = 2;

		this.cryptor = new Crypt(this.options);
		this.remoteName = false;

		socket.on(`${this.options.prefix}|${this.options.nameReqCmd}`, () => {
			socket.emit(`${this.options.prefix}|${this.options.nameReqCmdRet}`, name);
		});

		this.registerMiddlewareOut(async (packet) => {
			const id = packet.id;
			delete packet.id;
			return await this.cryptor.encrypt(authProvider.get(this.options.isServer ? this.remoteName : name), packet, id + '|' + socket.id,
				{v: this.options.iApiVersion, i: name});
		});

		this.registerMiddlewareInc(async (packet) => {
			if (!this.remoteName) {
				this.remoteName = await new Promise((resolve) => {
					socket.once(`${this.options.prefix}|${this.options.nameReqCmdRet}`, (p) => resolve(p));
					socket.emit(`${this.options.prefix}|${this.options.nameReqCmd}`);
				});
			}

			const data = await this.cryptor.decrypt(authProvider.get(this.options.isServer ? this.remoteName : name, false,
				(userData) => userData.v === this.options.iApiVersion && userData.i === this.remoteName), packet, true);

			if (!data || !data.id) return null;
			packet = data.payload;
			const idArr = data.id.split('|');
			if (idArr[1] !== socket.id) return null;
			packet.id = idArr[0];
			return packet;
		});
	}
}

module.exports = {
	IApiServer,
	IApiClient,
	IApiSimpleAuthProvider
};
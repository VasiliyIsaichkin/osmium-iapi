const {WebApiServer, WebApiClient} = require('osmium-webapi');
const {Crypt, oTools} = require('osmium-crypt');

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
		this.options.iApiVersion = 8;

		this.cryptor = new Crypt(this.options);
		this.remoteName = false;
		this.authMeta = false;

		socket.on(`${this.options.prefix}${this.options.nameReqCmd}`, () => {
			const authMeta = authProvider.getMeta ? authProvider.getMeta(this) : undefined;
			socket.emit(`${this.options.prefix}${this.options.nameReqCmdRet}`, {name, authMeta});
		});

		const encrypt = async ($socket, $packet, $id) => {
			if (this.isLocal) return;
			await this.requestRemoteName($socket);

			const sharedKey = authProvider.get(this.options.isServer, this.remoteName, name, this.authMeta, this.options.keySalt);
			const payload = await this.cryptor.encrypt(sharedKey, this.filterPacket($packet), $id + '|' + $socket.id,
				{v: this.options.iApiVersion, i: name});

			$packet.args = [payload];
		};

		const decrypt = async ($packet, $socket, $args) => {
			if (this.isLocal) return;
			await this.requestRemoteName($socket);

			const sharedKey = authProvider.get(this.options.isServer, this.remoteName, name, this.authMeta, this.options.keySalt,
				(userData) => userData.v === this.options.iApiVersion && userData.i === this.remoteName);
			const data = await this.cryptor.decrypt(sharedKey, $args[0], true);

			if (!data || !data.id) return null;
			Object.assign($packet, data.payload);

			const idArr = data.id.split('|');
			if (idArr[1] !== socket.id) return null;
		};


		this.middlewareIncBefore(this.PRIORITY.FIRST - 1, decrypt);
		this.middlewareIncAfter(this.PRIORITY.LAST + 1, encrypt);
		this.middlewareOutBefore(this.PRIORITY.LAST + 1, encrypt);
		this.middlewareOutAfter(this.PRIORITY.FIRST - 1, decrypt);
	}

	async requestRemoteName(socket) {
		if (this.remoteName) return;
		const ret = await new Promise((resolve) => {
			const cmd = `${this.options.prefix}${this.options.nameReqCmd}`;
			const iId = setInterval(() => socket.emit(cmd), 1000);
			socket.once(`${this.options.prefix}${this.options.nameReqCmdRet}`, (p) => {
				clearInterval(iId);
				resolve(p);
			});
			socket.emit(cmd);
		});

		this.remoteName = ret.name;
		this.authMeta = ret.authMeta;
	}
}

module.exports = {
	IApiServer,
	IApiClient
};

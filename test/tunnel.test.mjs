// dowss 隧道数据路径的回归测试：node test/tunnel.test.mjs
// 覆盖：响应头提前发、上行合包、下行 BYOB 大小包分流、首字节超时切代理后的重放、下行世代隔离。
// 注意：这是单进程测试，Worker 与 DO 共用同一个模块实例，且用 Node 的流实现；真机行为以部署后为准。
import { register } from 'node:module';
import assert from 'node:assert/strict';

const tick = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = new TextEncoder();
const dec = new TextDecoder();
const toText = (chunk) => dec.decode(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));

// Workerd 允许 new Response(null, { status: 101, webSocket })，Node 的 Response 不接受 101
const RealResponse = globalThis.Response;
globalThis.Response = class extends RealResponse {
	constructor(body, init) {
		if (init && init.status === 101) init = { ...init, status: 200 };
		super(body, init);
	}
};

// ---------- 假 WebSocket ----------
class FakeWS {
	constructor() { this.readyState = 1; this.listeners = {}; this.sent = []; }
	accept() { }
	addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
	send(data) { this.sent.push(data instanceof Uint8Array ? data : new Uint8Array(data)); }
	close() { this.readyState = 3; this.emit('close', {}); }
	emit(type, arg) { (this.listeners[type] || []).forEach((fn) => fn(arg)); }
}
globalThis.WebSocketPair = class {
	constructor() { this[0] = new FakeWS(); this[1] = new FakeWS(); globalThis.__lastPair = this; }
};

// ---------- 假 TCP socket ----------
function makeSocket({ closeEndsStream = true } = {}) {
	const writes = [];
	let controller = null;
	let closed = false;
	const readable = new ReadableStream({ type: 'bytes', start(c) { controller = c; } });
	const writable = new WritableStream({ write(chunk) { writes.push(toText(chunk)); } });
	return {
		writes,
		content: () => writes.join(''),
		isClosed: () => closed,
		opened: Promise.resolve({}),
		readable,
		writable,
		close() { closed = true; if (closeEndsStream) { try { controller.close(); } catch (_) { } } },
		push(data) { controller.enqueue(data instanceof Uint8Array ? data : new Uint8Array(data)); }
	};
}

// 假 request.fetcher：GrainTCP 的灰接口。代码从 request 上取 connect，测试里转到 socket 桩
function makeFetcher() {
	return {
		connect: (addr) => {
			const stub = globalThis.__socketStub;
			stub.calls.push(addr);
			return stub.handler(addr);
		}
	};
}

function installStub(options = {}) {
	const sockets = [];
	globalThis.__socketStub = {
		calls: [],
		handler: (addr) => {
			const s = makeSocket(options);
			sockets.push({ addr, s });
			return s;
		}
	};
	return sockets;
}

register(new URL('./stub-hooks.mjs', import.meta.url).href);
const mod = await import(new URL('../src/index.js', import.meta.url).href);
const worker = mod.default;
const WsDo = mod.WsDo;

const UUID = 'd87484d1-77a6-40bb-bac6-5b574bd7f61c';

function buildPacket(payload = 'HELLO', port = 443) {
	const hex = UUID.replace(/-/g, '');
	const payloadBytes = enc.encode(payload);
	const buf = new Uint8Array(26 + payloadBytes.length);
	let o = 0;
	buf[o++] = 0;
	for (let i = 0; i < 16; i++) buf[o++] = parseInt(hex.substr(i * 2, 2), 16);
	buf[o++] = 0;              // optLen
	buf[o++] = 1;              // cmd = TCP
	buf[o++] = port >> 8; buf[o++] = port & 0xff;
	buf[o++] = 1;              // atyp = IPv4
	buf[o++] = 1; buf[o++] = 1; buf[o++] = 1; buf[o++] = 1;
	buf.set(payloadBytes, o);
	return buf.buffer;
}

async function openTunnel(env = {}) {
	const instance = new WsDo({ waitUntil() { } }, { PYIP: '2001:db8::1', UUID4: UUID, ...env });
	const request = new Request('https://x.test/', { headers: { Upgrade: 'websocket' } });
	Object.defineProperty(request, 'fetcher', { value: makeFetcher(), configurable: true });
	const res = await instance.fetch(request);
	return { instance, res, serverSide: globalThis.__lastPair[1] };
}

let passed = 0;

// ================= T1 响应头提前发 + 直连并发拨号 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);

	assert.equal(sockets.length, 2, 'T1: 直连应并发拨号 2 路');
	assert.deepEqual(globalThis.__socketStub.calls[0], { hostname: '1.1.1.1', port: 443 });
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T1: 应有一条连接胜出');
	assert.deepEqual([...serverSide.sent[0]], [0, 0], 'T1: 响应头应单独、先于任何数据发出');
	assert.equal(winner.s.content(), 'HELLO', 'T1: 首包载荷应写入胜出连接');
	// 让远端回一次包，取消首字节超时定时器：否则它会在后续用例期间触发重试并污染 socket 计数
	winner.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T1 响应头提前单独发送；直连 2 路竞速，载荷写入胜出连接');
	passed++;
}

// ================= T2 上行合包 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);
	const winner = sockets.find((x) => !x.s.isClosed());

	const payload = [];
	for (let i = 0; i < 50; i++) {
		const chunk = String(i).padStart(4, '0').repeat(25);   // 每条 100 字节
		payload.push(chunk);
		serverSide.emit('message', { data: enc.encode(chunk).buffer });
	}
	await tick(80);

	assert.ok(winner.s.writes.length < 50, `T2: 50 条小消息应被合包，实际写了 ${winner.s.writes.length} 次`);
	assert.equal(winner.s.content(), 'HELLO' + payload.join(''), 'T2: 合包后内容与顺序必须完全一致');
	winner.s.push(new Uint8Array([1]));
	await tick(20);
	console.log(`T2 上行合包：50 条 100B 消息合成 ${winner.s.writes.length} 次写入，内容与顺序一致`);
	passed++;
}

// ================= T3 下行：BYOB 读 + 小包聚合 + 大包直发 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);
	const winner = sockets.find((x) => !x.s.isClosed());
	const headerCount = serverSide.sent.length;

	const downlink = [];
	for (let i = 0; i < 40; i++) {
		const chunk = String(i).padStart(4, '0').repeat(64);   // 每条 256 字节
		downlink.push(chunk);
		winner.s.push(enc.encode(chunk));
	}
	await tick(80);

	const downlinkSends = serverSide.sent.slice(headerCount).map(toText);
	assert.ok(downlinkSends.length < 40, `T3: 40 条 256B 小包应被聚合，实际发了 ${downlinkSends.length} 次`);
	assert.equal(downlinkSends.join(''), downlink.join(''), 'T3: 聚合后内容与顺序必须完全一致');

	// 大包直发：>= 32KB 不走聚合，直接 send
	// 注意：Node 的 byte stream enqueue() 会转移传入 TypedArray 的底层缓冲，所以比较基准要先留一份拷贝
	const big = new Uint8Array(64 * 1024).fill(65);
	const bigExpected = big.slice();
	winner.s.push(big);
	await tick(40);
	const lastSent = serverSide.sent.at(-1);
	assert.equal(lastSent.byteLength, 64 * 1024, 'T3: 大包应原样直发');
	assert.deepEqual(lastSent, bigExpected, 'T3: 大包内容不能被改写（复用读缓冲会让它错乱）');
	console.log(`T3 下行小包 40 条聚合成 ${downlinkSends.length} 次发送；64KB 大包直发且内容不变`);
	passed++;
}

// ================= T4 首字节超时切代理：重放 + 世代隔离 =================
{
	const sockets = installStub({ closeEndsStream: false });
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);
	const direct = sockets.find((x) => !x.s.isClosed());
	serverSide.emit('message', { data: enc.encode('WORLD').buffer });
	await tick(40);

	// 直连一直不回包 → 3.5s 后应切到 PYIP
	await tick(3700);
	assert.equal(sockets.length, 3, 'T4: 首字节超时应触发一次代理重试');
	assert.deepEqual(globalThis.__socketStub.calls[2], { hostname: '2001:db8::1', port: 443 }, 'T4: 应连向 PYIP(裸 IPv6 当主机)');
	const proxy = sockets[2].s;
	assert.equal(proxy.content(), 'HELLOWORLD', 'T4: 已写入旧连接的数据必须在新连接上重放');

	// 世代隔离：旧连接迟到的数据不能再写进 WS
	const sentCount = serverSide.sent.length;
	direct.s.push(enc.encode('LATE'));
	await tick(60);
	assert.equal(serverSide.sent.length, sentCount, 'T4: 旧连接迟到的数据不能写进 WS');

	// 当前连接的数据正常回传
	proxy.push(enc.encode('REPLY'));
	await tick(60);
	assert.ok(toText(serverSide.sent.at(-1)).includes('REPLY'), 'T4: 当前连接的数据应正常回传');
	console.log('T4 超时切代理后重放完整（HELLOWORLD）；旧连接迟到数据被世代隔离；新连接回传正常');
	passed++;
}

// ================= T5 非 WS 请求仍走 nginx 伪装页 =================
{
	const env = { REGION: 'wnam', UUID4: UUID, DO_SHARDS: '1', WS_DO: { idFromName: (n) => ({ n }), get: () => ({ fetch: async () => ({ route: 'do' }) }) } };
	const r1 = await worker.fetch(new Request('https://x.test/'), env);
	assert.equal(r1.status, 200, 'T5: 首页应 200');
	assert.match(await r1.text(), /Welcome to nginx!/, 'T5: 首页应是 nginx 欢迎页');
	const r2 = await worker.fetch(new Request('https://x.test/foo'), env);
	assert.equal(r2.status, 404, 'T5: 其它路径应 404');
	const r3 = await worker.fetch(new Request('https://x.test/', { headers: { Upgrade: 'WebSocket' } }), env);
	assert.deepEqual(r3, { route: 'do' }, 'T5: Upgrade 大小写不敏感');
	console.log('T5 非 WS 仍走 nginx 伪装页，Upgrade 大小写不敏感');
	passed++;
}

// ================= T6 拨号超时：SYN 被丢弃时不能干等，必须走代理兜底 =================
{
	const sockets = [];
	globalThis.__socketStub = {
		calls: [],
		handler: (addr) => {
			const isDirect = addr.hostname !== '2001:db8::1';
			const s = makeSocket();
			// 直连模拟"丢 SYN"：opened 永不 resolve，只有拨号超时才能救
			if (isDirect) s.opened = new Promise(() => { });
			sockets.push({ addr, s, isDirect });
			return s;
		}
	};
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(2600);   // DIAL_TIMEOUT 是 2s，留点余量

	const proxy = sockets.find((x) => !x.isDirect);
	assert.ok(proxy, 'T6: 直连拨号超时后必须切到代理兜底');
	assert.equal(proxy.s.content(), 'HELLO', 'T6: 切到代理时要重放已写入的数据');
	proxy.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T6 直连丢 SYN → 拨号超时 → 切代理并重放');
	passed++;
}

console.log(`\n全部通过：${passed} 项`);

// dowss 隧道数据路径的回归测试：node test/tunnel.test.mjs
// 覆盖：响应头提前发、上行合包、下行 BYOB 大小包分流、首字节超时切代理后的重放、下行世代隔离、
//       客户端断开收尾、重试耗尽、上行写失败重连、队列条目上限、early data 校验、下行背压、DoH 回退/缓存、协议头边界、PYIP 端口规则。
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
	constructor() { this.readyState = 1; this.listeners = {}; this.sent = []; this.bufferedAmount = 0; }
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
function makeSocket({ closeEndsStream = true, writeError = false, readError = false } = {}) {
	const writes = [];
	let controller = null;
	let closed = false;
	const readable = new ReadableStream({
		type: 'bytes',
		start(c) {
			controller = c;
			if (readError) c.error(new Error('read failed'));
		}
	});
	const writable = new WritableStream({ write(chunk) { if (writeError) throw new Error('write failed'); writes.push(toText(chunk)); } });
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

// 构造 ATYP=3（IPv6）的 VLESS 请求头
function buildPacketV6(groups, payload = 'HELLO', port = 443) {
	const hex = UUID.replace(/-/g, '');
	const payloadBytes = enc.encode(payload);
	const buf = new Uint8Array(42 + payloadBytes.length);
	let o = 0;
	buf[o++] = 0;
	for (let i = 0; i < 16; i++) buf[o++] = parseInt(hex.substr(i * 2, 2), 16);
	buf[o++] = 0;              // optLen
	buf[o++] = 1;              // cmd = TCP
	buf[o++] = port >> 8; buf[o++] = port & 0xff;
	buf[o++] = 3;              // atyp = IPv6
	for (let i = 0; i < 8; i++) { const v = groups[i] || 0; buf[o++] = v >> 8; buf[o++] = v & 0xff; }
	buf.set(payloadBytes, o);
	return buf.buffer;
}

async function openTunnel(env = {}, headers = {}) {
	const instance = new WsDo({ waitUntil() { } }, { PYIP: '2001:db8::1', UUID4: UUID, ...env });
	const request = new Request('https://x.test/', { headers: { Upgrade: 'websocket', ...headers } });
	Object.defineProperty(request, 'fetcher', { value: makeFetcher(), configurable: true });
	const res = await instance.fetch(request);
	return { instance, res, serverSide: globalThis.__lastPair[1] };
}

const toBase64Url = (buffer) => Buffer.from(buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer).toString('base64url');

const frameUdp = (payload) => {
	const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
	const framed = new Uint8Array(2 + bytes.byteLength);
	framed[0] = bytes.byteLength >> 8;
	framed[1] = bytes.byteLength & 0xff;
	framed.set(bytes, 2);
	return framed;
};

function buildUdpPacket(dnsQuery, port = 53) {
	const hex = UUID.replace(/-/g, '');
	const payload = frameUdp(dnsQuery);
	const buf = new Uint8Array(26 + payload.byteLength);
	let o = 0;
	buf[o++] = 0;
	for (let i = 0; i < 16; i++) buf[o++] = parseInt(hex.substr(i * 2, 2), 16);
	buf[o++] = 0;              // optLen
	buf[o++] = 2;              // cmd = UDP
	buf[o++] = port >> 8; buf[o++] = port & 0xff;
	buf[o++] = 1;              // atyp = IPv4
	buf[o++] = 1; buf[o++] = 1; buf[o++] = 1; buf[o++] = 1;
	buf.set(payload, o);
	return buf.buffer;
}

function makeDnsQuery(id, name = 'example.com') {
	const labels = [];
	for (const label of name.split('.')) {
		const bytes = enc.encode(label);
		labels.push(bytes.byteLength, ...bytes);
	}
	return new Uint8Array([id >> 8, id & 0xff, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1]);
}

let passed = 0;

// ================= T1 建连后立刻回响应头 + 直连并发拨号 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);

	assert.equal(sockets.length, 2, 'T1: 直连应并发拨号 2 路');
	assert.deepEqual(globalThis.__socketStub.calls[0], { hostname: '1.1.1.1', port: 443 });
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T1: 应有一条连接胜出');
	// 关键不变式之一：建连成功就要回响应头，且不依赖客户端先给数据
	assert.deepEqual([...serverSide.sent[0]], [0, 0], 'T1: 建连后应立刻回响应头');
	assert.equal(serverSide.sent.length, 1, 'T1: 建连后只应发这一帧响应头');
	assert.equal(winner.s.content(), 'HELLO', 'T1: 首包载荷应写入胜出连接');
	// 让远端回一次包，取消首字节超时定时器
	winner.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T1 建连后立刻回响应头（不等下行数据）；直连 2 路竞速，载荷写入胜出连接');
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

	const downlink = [];
	for (let i = 0; i < 40; i++) {
		const chunk = String(i).padStart(4, '0').repeat(64);   // 每条 256 字节
		downlink.push(chunk);
		winner.s.push(enc.encode(chunk));
	}
	await tick(80);

	// sent[0] 是随首条下行数据发出的 2 字节响应头，之后才是数据
	assert.deepEqual([...serverSide.sent[0]], [0, 0], 'T3: 响应头应在首条下行数据前发出');
	const downlinkSends = serverSide.sent.slice(1).map(toText);
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

// ================= T7 首包无载荷时也要回响应头 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	// 只发 VLESS 头、不带任何载荷：模拟"先建连、等响应头、再发业务数据"的客户端（sing-box 就是这种）
	serverSide.emit('message', { data: buildPacket('') });
	await tick(60);
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T7: 应有一条连接胜出');
	assert.deepEqual([...serverSide.sent[0]], [0, 0], 'T7: 建连后必须立刻回响应头，不能等客户端先给数据');
	assert.equal(winner.s.content(), '', 'T7: 没有载荷时不应往目标写数据');
	winner.s.push(new Uint8Array([1]));   // 取消首字节超时定时器
	await tick(20);
	console.log('T7 首包无载荷也要回响应头（否则与等响应头的客户端互相死等）');
	passed++;
}

// ================= T8 IPv6 目标拨号地址必须带方括号 =================
{
	globalThis.__socketStub = { calls: [], handler: () => makeSocket() };
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacketV6([0x2001, 0x4860, 0x4828, 0x7700, 0, 0, 0, 0]) });
	await tick(200);
	assert.equal(
		globalThis.__socketStub.calls[0].hostname,
		'[2001:4860:4828:7700:0:0:0:0]',
		`T8: IPv6 目标拨号必须带方括号，实际: ${JSON.stringify(globalThis.__socketStub.calls[0])}`
	);
	// 关掉连接，别让首字节超时重试链把测试进程额外挂 14 秒
	serverSide.close();
	await tick(20);
	console.log('T8 IPv6 目标拨号地址带方括号（不带时边缘判定为非法地址）');
	passed++;
}

// ================= T9 客户端断开后必须关闭出站 socket =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T9: 应有一条连接胜出');
	serverSide.close();
	await tick(60);
	assert.equal(winner.s.isClosed(), true, 'T9: 客户端断开后出站 socket 必须关闭');
	console.log('T9 客户端断开会关闭出站 socket，不再把 DO 与 socket 挂到远端 EOF');
	passed++;
}

// ================= T10 未配置 PYIP：首字节超时后必须关 WS =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel({ PYIP: '' });
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(3700);
	assert.equal(sockets.length, 2, 'T10: 直连仍应并发拨号 2 路');
	assert.equal(serverSide.readyState, 3, 'T10: 无 PYIP 可重试时必须关闭 WS，不能让客户端挂死');
	console.log('T10 无 PYIP 且直连无回包：3.5s 后关闭 WS');
	passed++;
}

// ================= T11 非 VLESS 的 sec-websocket-protocol 不能当首包 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel({}, { 'sec-websocket-protocol': 'binary' });
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(100);
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T11: 普通子协议不应打断连接');
	assert.equal(winner.s.content(), 'HELLO', 'T11: 普通子协议应被忽略，后续 WS 消息正常建连');
	winner.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T11 非 VLESS 的 early data 头被忽略，连接继续');
	passed++;
}

// ================= T12 合法 early data（base64url 无 padding）仍能建连 =================
{
	const sockets = installStub();
	const header = toBase64Url(buildPacket('HELLO'));
	const { serverSide } = await openTunnel({}, { 'sec-websocket-protocol': header });
	await tick(100);
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T12: 合法 early data 应直接建连');
	assert.equal(winner.s.content(), 'HELLO', 'T12: early data 的载荷应写入目标');
	winner.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T12 合法 early data（无 padding）校验 UUID 后建连并写入首包');
	passed++;
}

// ================= T13 截断的 VLESS 头必须关闭 WS 且不拨号 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO').slice(0, 20) });
	await tick(60);
	assert.equal(sockets.length, 0, 'T13: 截断的 VLESS 头不应拨号');
	assert.equal(serverSide.readyState, 3, 'T13: 解析失败应关闭 WS');
	console.log('T13 截断的 VLESS 头：不拨号，关闭 WS');
	passed++;
}

// ================= T14 上行写失败：切 PYIP 并重放 =================
{
	const sockets = [];
	globalThis.__socketStub = {
		calls: [],
		handler: (addr) => {
			const isProxy = addr.hostname === 'proxyip.test';
			const s = makeSocket({ writeError: !isProxy });
			sockets.push({ addr, s, isProxy });
			return s;
		}
	};
	const { serverSide } = await openTunnel({ PYIP: 'proxyip.test:8443' });
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(300);
	const proxy = sockets.find((x) => x.isProxy);
	assert.ok(proxy, 'T14: 上行写失败后应切到 PYIP');
	assert.deepEqual(
		globalThis.__socketStub.calls.at(-1),
		{ hostname: 'proxyip.test', port: 8443 },
		'T14: PYIP 写成 host:port 时应使用该端口'
	);
	assert.equal(proxy.s.content(), 'HELLO', 'T14: 切代理后要重放已写失败的数据');
	proxy.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T14 上行写失败切 PYIP 并重放；PYIP 的 host:port 生效');
	passed++;
}

// ================= T15 下行背压：缓冲高水位暂停发送 =================
{
	const sockets = installStub();
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(60);
	const winner = sockets.find((x) => !x.s.isClosed());
	assert.ok(winner, 'T15: 应有一条连接胜出');
	const before = serverSide.sent.length;
	serverSide.bufferedAmount = 5 * 1024 * 1024;
	winner.s.push(enc.encode('BLOCKED'));
	await tick(100);
	assert.equal(serverSide.sent.length, before, 'T15: WS 缓冲高水位时应暂停下行');
	serverSide.bufferedAmount = 0;
	await tick(150);
	assert.equal(serverSide.sent.length, before + 1, 'T15: 缓冲回落后应继续发送');
	assert.ok(toText(serverSide.sent.at(-1)).includes('BLOCKED'), 'T15: 恢复后内容必须完整');
	winner.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T15 WS 缓冲高水位暂停下行，回落后继续');
	passed++;
}

// ================= T16 上行队列条目上限：1 字节帧也不能无限堆 =================
{
	const rejects = [];
	globalThis.__socketStub = {
		calls: [],
		handler: () => {
			const s = makeSocket();
			// 拨号一直不落地，让 inbound 队列来不及被消费
			s.opened = new Promise((_, reject) => rejects.push(reject));
			return s;
		}
	};
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	for (let i = 0; i < 4100; i++) serverSide.emit('message', { data: new Uint8Array([1]).buffer });
	await tick(50);
	assert.equal(serverSide.readyState, 3, 'T16: 队列条目超限应关闭 WS');
	rejects.forEach((reject) => reject(new Error('blocked')));
	await tick(50);
	console.log('T16 上行队列条目上限生效（4096 条）');
	passed++;
}

// ================= T17 DoH：首个服务失败回退，第二个查询命中缓存 =================
{
	const originalFetch = globalThis.fetch;
	const dnsQuery1 = makeDnsQuery(0x1234);
	const dnsQuery2 = makeDnsQuery(0x5678);
	let calls = 0;
	globalThis.fetch = async () => {
		calls++;
		if (calls === 1) throw new Error('primary DoH down');
		const response = dnsQuery1.slice();
		response[2] = 0x81;   // QR=1, RD=1
		response[3] = 0x80;   // RA=1
		return new Response(response, { status: 200 });
	};
	try {
		const { serverSide } = await openTunnel();
		serverSide.emit('message', { data: buildUdpPacket(dnsQuery1) });
		await tick(100);
		assert.ok(serverSide.sent.length >= 1, 'T17: 应收到 DoH 响应');
		const first = new Uint8Array(serverSide.sent[0]);
		assert.deepEqual([...first.subarray(0, 2)], [0, 0], 'T17: 首个 UDP 响应要带 VLESS 响应头');
		const firstLen = (first[2] << 8) | first[3];
		assert.equal(firstLen, dnsQuery1.byteLength, 'T17: 响应长度必须正确');
		assert.equal(first[4], 0x12, 'T17: 响应 ID 应与首个查询一致');
		assert.equal(first[5], 0x34, 'T17: 响应 ID 应与首个查询一致');

		serverSide.emit('message', { data: frameUdp(dnsQuery2).buffer });
		await tick(100);
		assert.equal(calls, 2, 'T17: 首个 DoH 服务失败应回退；第二个相同查询应命中缓存');
		const second = new Uint8Array(serverSide.sent[1]);
		const secondLen = (second[0] << 8) | second[1];
		assert.equal(secondLen, dnsQuery2.byteLength, 'T17: 缓存响应的长度必须正确');
		assert.equal(second[2], 0x56, 'T17: 缓存命中的响应 ID 要改回本次查询 ID');
		assert.equal(second[3], 0x78, 'T17: 缓存命中的响应 ID 要改回本次查询 ID');
		console.log('T17 DoH 主服务失败回退备用服务，相同查询命中缓存并回填 ID');
		passed++;
	} finally {
		globalThis.fetch = originalFetch;
	}
}

// ================= T18 最后一次代理重试无回包也要关 WS =================
{
	let proxyAttempts = 0;
	globalThis.__socketStub = {
		calls: [],
		handler: (addr) => {
			if (addr.hostname !== '2001:db8::1') {
				const s = makeSocket();
				s.opened = Promise.reject(new Error('direct blocked'));
				s.opened.catch(() => { });
				return s;
			}
			proxyAttempts++;
			// 前两次代理连接立刻读失败，第三次黑hole：只有首字节超时能收尾
			return makeSocket({ readError: proxyAttempts <= 2 });
		}
	};
	const { serverSide } = await openTunnel();
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(3700);
	assert.equal(proxyAttempts, 3, 'T18: 应打满 3 次代理重试');
	assert.equal(serverSide.readyState, 3, 'T18: 最后一次代理无回包时必须关 WS');
	console.log('T18 最后一次代理重试无回包：3.5s 后关闭 WS，不再无限等');
	passed++;
}

// ================= T19 PYIP 不写端口：默认 443，不跟随目标端口 =================
{
	const sockets = [];
	globalThis.__socketStub = {
		calls: [],
		handler: (addr) => {
			const isProxy = addr.hostname === 'proxyip.test';
			const s = makeSocket({ writeError: !isProxy });
			sockets.push({ addr, s, isProxy });
			return s;
		}
	};
	const { serverSide } = await openTunnel({ PYIP: 'proxyip.test' });
	serverSide.emit('message', { data: buildPacket('HELLO', 8443) });
	await tick(300);
	const proxy = sockets.find((x) => x.isProxy);
	assert.ok(proxy, 'T19: 写失败后应切到 PYIP');
	assert.deepEqual(
		globalThis.__socketStub.calls.at(-1),
		{ hostname: 'proxyip.test', port: 443 },
		'T19: PYIP 不写端口时默认 443，不能用目标端口 8443'
	);
	assert.equal(proxy.s.content(), 'HELLO', 'T19: 切代理后要重放已写失败的数据');
	proxy.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T19 PYIP 不写端口默认 443，不跟随目标端口');
	passed++;
}

// ================= T20 PYIP 的 .tp<port> 覆盖端口 =================
{
	const sockets = [];
	globalThis.__socketStub = {
		calls: [],
		handler: (addr) => {
			const isProxy = addr.hostname !== '1.1.1.1';
			const s = makeSocket({ writeError: !isProxy });
			sockets.push({ addr, s, isProxy });
			return s;
		}
	};
	const { serverSide } = await openTunnel({ PYIP: 'proxyip.test.tp2053' });
	serverSide.emit('message', { data: buildPacket('HELLO') });
	await tick(300);
	const proxy = sockets.find((x) => x.isProxy);
	assert.ok(proxy, 'T20: 写失败后应切到 PYIP');
	assert.deepEqual(
		globalThis.__socketStub.calls.at(-1),
		{ hostname: 'proxyip.test.tp2053', port: 2053 },
		'T20: .tp2053 应覆盖默认端口'
	);
	assert.equal(proxy.s.content(), 'HELLO', 'T20: 切代理后要重放已写失败的数据');
	proxy.s.push(new Uint8Array([1]));
	await tick(20);
	console.log('T20 PYIP 域名里的 .tp2053 覆盖默认端口');
	passed++;
}

console.log(`\n全部通过：${passed} 项`);

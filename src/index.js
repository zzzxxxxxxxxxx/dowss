import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

const textDecoder = new TextDecoder();

// WebSocket readyState 常量
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// DNS over HTTPS 服务地址
const DOH_SERVER = 'https://1.1.1.1/dns-query';

// 首字节超时：直连/代理连接后若在此时间内无数据返回，触发 retry
const FIRST_BYTE_TIMEOUT = 3500;

// 单次拨号超时：目标丢 SYN 时 connect() 会等系统级超时（几十秒），必须自己兜住才能走代理兜底
const DIAL_TIMEOUT = 2000;

// 协议常量
const ADDR_TYPE_IPV4 = 1;
const ADDR_TYPE_DOMAIN = 2;
const ADDR_TYPE_IPV6 = 3;
const COMMAND_TCP = 1;
const COMMAND_UDP = 2;

// early data（sec-websocket-protocol 携带的首包）头长上限，超长一律不按 early data 处理
const EARLY_DATA_MAX_HEADER_LENGTH = Math.ceil(8 * 1024 * 4 / 3) + 4;

// 直连并发拨号数：多路同时建连取最快的一条，吃掉 CF 路由层的黑盒抖动
const CONCURRENT_DIALS = 2;

// 上行重放缓冲上限：切连接时补发「已写入旧连接、远端还没回包」的数据
const UPLINK_REPLAY_LIMIT = 256 * 1024;

// 上行队列上限：WS 消息进 ReadableStream 不受背压约束，客户端猛灌时必须有个硬上限
const UPLINK_QUEUE_LIMIT = 16 * 1024 * 1024;

// 上行合包目标：连续小块并到这个大小再写一次 socket，减少 writer.write() 次数
const UPLINK_PACK_TARGET = 20 * 1024;

// 下行：BYOB 读块大小、小包聚合上限、尾部阈值、低水位、连续增长最多观察轮次
const DOWNLINK_READ_CHUNK = 64 * 1024;
const DOWNLINK_PACK_LIMIT = 32 * 1024;
const DOWNLINK_TAIL = 512;
const DOWNLINK_LOW_WATER = Math.max(4096, DOWNLINK_TAIL * 12);
const DOWNLINK_QUIET_ROUNDS = 4;

/* ---------- 伪装页面 ---------- */
const NGINX_WELCOME = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;

const NGINX_404 = `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`;

// 非 WebSocket 请求一律走这里：首页给 nginx 默认欢迎页，其余路径给 nginx 风格 404
function nginxResponse(url) {
	const isIndex = url.pathname === '/' || url.pathname === '/index.html';
	return new Response(isIndex ? NGINX_WELCOME : NGINX_404, {
		status: isIndex ? 200 : 404,
		headers: { 'Content-Type': 'text/html; charset=UTF-8' },
	});
}

// Upgrade 头按大小写不敏感比较，客户端发 WebSocket 也要认
function isWebSocketUpgrade(request) {
	return (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket';
}

/* ---------- UUID / Base64 工具函数 ---------- */

function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

function userIdToUint8Array(uuid) {
	if (!uuid || !isValidUUID(uuid)) throw new Error("Invalid UUID format");
	const hex = uuid.replace(/-/g, "");
	if (hex.length !== 32) throw new Error("Invalid UUID format");
	const arr = new Uint8Array(16);
	for (let i = 0; i < 16; ++i) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
	return arr;
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) return { error: null };
	try {
		// 运行时支持原生 base64url 解码时走原生路径，省掉逐字符回调
		if (typeof Uint8Array.fromBase64 === 'function') {
			const decoded = Uint8Array.fromBase64(base64Str, { alphabet: 'base64url' });
			return { earlyData: decoded.buffer, error: null };
		}
		base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
		const decoded = atob(base64Str);
		const arr = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
		return { earlyData: arr.buffer, error: null };
	} catch (e) {
		return { error: e };
	}
}

/* ---------- host:port 解析 ---------- */

function splitHostPort(address) {
	const str = String(address).trim();

	// ---------- IPv6：形如 "[IPv6]" 或 "[IPv6]:port" ----------
	if (str.startsWith('[')) {
		const endBracket = str.indexOf(']');
		if (endBracket !== -1) {
			const host = str.slice(0, endBracket + 1);   // 包含方括号
			const after = str.slice(endBracket + 1);     // 可能是 ":port" 或空端口
			const port = after.startsWith(':') ? Number(after.slice(1)) : 443;
			return { host, port };
		}
	}

	// ---------- 其它形式： host[:port]（IPv4、域名、裸 IPv6 都走这里） ----------
	// 只在「恰好一个冒号」时才当 host:port，否则裸 IPv6（如 2001:db8::1）会被最后一段数字误判成端口
	const colonIdx = str.lastIndexOf(':');
	if (colonIdx > -1 && str.indexOf(':') === colonIdx) {
		const possiblePort = str.slice(colonIdx + 1);
		if (/^\d+$/.test(possiblePort)) {
			const host = str.slice(0, colonIdx);
			const port = Number(possiblePort);
			return { host, port };
		}
	}

	// ---------- 没有端口的普通情况 ----------
	return { host: str, port: 443 };
}

/* ---------- 协议头解析 ---------- */
function parseProtocolHeader(buffer, userIDUint8Array) {
	if (!buffer || buffer.byteLength < 24) return { hasError: true, message: "Too short" };
	const view = new Uint8Array(buffer);
	// UUID 校验：展开成固定位置比较，省掉循环与偏移计算（UUID 已在实例构造时预解码成 16 字节）
	const id = userIDUint8Array;
	if (view[1] !== id[0] || view[2] !== id[1] || view[3] !== id[2] || view[4] !== id[3] ||
		view[5] !== id[4] || view[6] !== id[5] || view[7] !== id[6] || view[8] !== id[7] ||
		view[9] !== id[8] || view[10] !== id[9] || view[11] !== id[10] || view[12] !== id[11] ||
		view[13] !== id[12] || view[14] !== id[13] || view[15] !== id[14] || view[16] !== id[15]) {
		return { hasError: true, message: "Unauthorized UUID" };
	}
	const optLength = view[17];
	let pos = 18 + optLength + 1;

	// 命令类型：TCP / UDP
	const command = view[18 + optLength];
	const isUDP = command === COMMAND_UDP;

	const port = (view[pos] << 8) | view[pos + 1];
	pos += 2;

	const addrType = view[pos++];
	let address = "";
	if (addrType === ADDR_TYPE_IPV4) {
		// IPv4
		address = `${view[pos++]}.${view[pos++]}.${view[pos++]}.${view[pos++]}`;
	} else if (addrType === ADDR_TYPE_DOMAIN) {
		// 域名
		const len = view[pos++];
		address = textDecoder.decode(view.subarray(pos, pos + len));
		pos += len;
	} else if (addrType === ADDR_TYPE_IPV6) {
		// IPv6：使用 DataView 一次性读取 16 字节
		const dv = new DataView(buffer, pos, 16);
		const parts = [];
		for (let i = 0; i < 8; ++i) {
			parts.push(dv.getUint16(i * 2).toString(16));
		}
		address = parts.join(":");
		pos += 16;
	} else {
		return { hasError: true, message: `Invalid address type ${addrType}` };
	}

	return {
		hasError: false,
		addressRemote: address,
		portRemote: port,
		// 用视图而不是 slice：少一次拷贝；WS 消息的 ArrayBuffer 是独立的，不会被运行时复用
		rawClientData: view.subarray(pos),
		addressType: addrType,
		responseHeader: new Uint8Array([view[0], 0]),
		isUDP,
	};
}

/* ---------- 读取 WebSocket 为 ReadableStream ---------- */
// queueCounter 用于约束「已入队但还没被消费」的上行字节：controller.enqueue 不受背压约束，客户端猛灌时会无限堆积
function makeReadableWebSocketStream(ws, earlyDataHeader, log, queueCounter) {
	let cancelled = false;
	ws.binaryType = 'arraybuffer';
	// 超长头不按 early data 解，避免异常客户端用超大 sec-websocket-protocol 撑爆内存
	const { earlyData, error } = (earlyDataHeader && earlyDataHeader.length <= EARLY_DATA_MAX_HEADER_LENGTH)
		? base64ToArrayBuffer(earlyDataHeader)
		: { error: null };
	const stream = new ReadableStream({
		start(controller) {
			const admit = (data) => {
				const length = data?.byteLength ?? 0;
				if (queueCounter && queueCounter.bytes + length > UPLINK_QUEUE_LIMIT) {
					cancelled = true;
					log(`上行队列超限（>${UPLINK_QUEUE_LIMIT}B），关闭连接`);
					safeCloseWebSocket(ws);
					try { controller.error(new Error("uplink queue overflow")); } catch (_) { }
					return false;
				}
				if (queueCounter) queueCounter.bytes += length;
				return true;
			};
			ws.addEventListener("message", (e) => {
				if (cancelled) return;
				if (!admit(e.data)) return;
				controller.enqueue(e.data);
			});
			ws.addEventListener("close", () => {
				if (!cancelled) controller.close();
			});
			ws.addEventListener("error", (e) => {
				controller.error(e);
			});
			if (error) {
				controller.error(error);
			} else if (earlyData && admit(earlyData)) {
				controller.enqueue(earlyData);
			}
		},
		cancel(reason) {
			cancelled = true;
			log(`readableStream canceled: ${reason}`);
			safeCloseWebSocket(ws);
		},
	});
	return stream;
}

/* ---------- grain 收纳核：把连续小块并成更少的写入 ---------- */
// copy=true 时合并结果会 slice 出一份新缓冲：ws.send 不深拷贝，会一直持有这块 backing store
function makeGrainKernel(cap, copy) {
	let queue = [], head = 0, bytes = 0, mergeBuffer = null;
	const isEmpty = () => head >= queue.length;
	const compact = () => { if (head > 32 && head * 2 >= queue.length) { queue = queue.slice(head); head = 0; } };
	const store = (chunk) => {
		const length = chunk?.byteLength || 0;
		if (!length) return false;
		queue.push(chunk);
		bytes += length;
		return true;
	};
	// 取队头一块，并把后面还能塞进 cap 的连续块并进来
	const bundle = () => {
		if (isEmpty()) return null;
		const first = queue[head];
		queue[head++] = undefined;
		bytes -= first.byteLength;
		let length = first.byteLength, j = head;
		while (j < queue.length) {
			const total = length + queue[j].byteLength;
			if (total > cap) break;
			length = total; j++;
		}
		let result = first, usedSharedBuffer = false;
		if (j > head) {
			const output = mergeBuffer ||= new Uint8Array(cap);
			output.set(first);
			let offset = first.byteLength;
			while (head < j) {
				const next = queue[head];
				queue[head++] = undefined;
				bytes -= next.byteLength;
				output.set(next, offset);
				offset += next.byteLength;
			}
			result = output.subarray(0, length);
			usedSharedBuffer = true;
		}
		compact();
		// 只有合并结果落在复用缓冲上时才需要拷出来：ws.send 会一直持有这块 backing store
		return (copy && usedSharedBuffer) ? result.slice() : result;
	};
	return { isEmpty, size: () => bytes, store, bundle };
}

/* ---------- 下行门控：小包先聚合，攒够上限或安静下来再发 ---------- */
function makeDownlinkGate(ws, isAlive) {
	const kernel = makeGrainKernel(DOWNLINK_PACK_LIMIT, true);
	let timer = null, gen = 0, lastGen = 0, quietRounds = 0;

	const flushNow = () => {
		if (timer) { clearTimeout(timer); timer = null; }
		quietRounds = 0;
		for (;;) {
			const chunk = kernel.bundle();
			if (!chunk) break;
			if (isAlive()) ws.send(chunk);
		}
	};

	const scheduleFlush = () => {
		if (kernel.isEmpty() || timer) return;
		if (kernel.size() >= DOWNLINK_PACK_LIMIT || DOWNLINK_PACK_LIMIT - kernel.size() < DOWNLINK_TAIL) return flushNow();
		timer = setTimeout(() => {
			timer = null;
			if (kernel.isEmpty()) return;
			if (kernel.size() >= DOWNLINK_PACK_LIMIT || DOWNLINK_PACK_LIMIT - kernel.size() < DOWNLINK_TAIL) return flushNow();
			// 还在连续增长、或还没到低水位，就再多观察一轮
			if (quietRounds < DOWNLINK_QUIET_ROUNDS && (gen !== lastGen || kernel.size() < DOWNLINK_LOW_WATER)) {
				quietRounds++;
				lastGen = gen;
				return scheduleFlush();
			}
			flushNow();
		}, 1);
	};

	return {
		send(chunk) {
			const length = chunk?.byteLength || 0;
			if (!length) return;
			let offset = 0;
			while (offset < length) {
				const writable = Math.min(DOWNLINK_PACK_LIMIT - kernel.size(), length - offset);
				if (!writable) { flushNow(); continue; }
				kernel.store(offset || writable !== length ? chunk.subarray(offset, offset + writable) : chunk);
				gen++;
				offset += writable;
				if (kernel.size() >= DOWNLINK_PACK_LIMIT || DOWNLINK_PACK_LIMIT - kernel.size() < DOWNLINK_TAIL) flushNow();
				else scheduleFlush();
			}
		},
		flush: flushNow,
	};
}

/* ---------- 下行泵：BYOB 读，大包直发、小包聚合 ---------- */
async function pumpDownlink(readable, ws, isAlive, onFirstChunk) {
	const reader = readable.getReader({ mode: 'byob' });
	const gate = makeDownlinkGate(ws, isAlive);
	let buffer = new ArrayBuffer(DOWNLINK_READ_CHUNK);
	let sawFirstChunk = false;
	try {
		for (;;) {
			const { done, value } = await reader.read(new Uint8Array(buffer, 0, DOWNLINK_READ_CHUNK));
			if (done) break;
			if (!value?.byteLength) continue;
			if (!sawFirstChunk) {
				sawFirstChunk = true;
				onFirstChunk && onFirstChunk();
			}
			if (value.byteLength >= (DOWNLINK_READ_CHUNK >> 1)) {
				// 大包直发：send 之后这块读缓冲被 runtime 持有，必须立刻换一块新的
				gate.flush();
				if (isAlive()) ws.send(value);
				buffer = new ArrayBuffer(DOWNLINK_READ_CHUNK);
			} else {
				// 小包：先 slice 脱离读缓冲，再把读缓冲还回去复用
				gate.send(value.slice());
				buffer = value.buffer;
			}
		}
		gate.flush();
	} catch (_) {
		// socket 被关闭（对端断开，或切代理时我们主动 close）属于正常收尾，
		// 挂起的 BYOB 读会抛 "This socket has been closed"；后续由上层按 hasIncoming/retry 决定
	} finally {
		try { gate.flush(); } catch (_) { }
		try { reader.releaseLock(); } catch (_) { }
	}
}

/* ---------- 下行中继：首字节超时切代理；世代失效后不再往 WS 写 ---------- */
async function relayDownlink(remoteSocket, ws, retry, log, isAlive, onFirstChunk) {
	let hasIncoming = false;
	let retryTriggered = false;
	let firstByteTimer = null;

	// 首字节超时：指定时间内没有回包就强制关闭 socket 触发 retry
	if (retry) {
		firstByteTimer = setTimeout(() => {
			if (!hasIncoming && !retryTriggered) {
				retryTriggered = true;
				log && log(`no data within ${FIRST_BYTE_TIMEOUT}ms, triggering retry`);
				try { remoteSocket.close(); } catch (_) { }
				retry();
			}
		}, FIRST_BYTE_TIMEOUT);
	}

	try {
		await pumpDownlink(remoteSocket.readable, ws, isAlive, () => {
			if (hasIncoming) return;
			hasIncoming = true;
			if (firstByteTimer) { clearTimeout(firstByteTimer); firstByteTimer = null; }
			onFirstChunk && onFirstChunk();
		});
	} catch (e) {
		console.error("downlink error:", e);
	}

	if (firstByteTimer) { clearTimeout(firstByteTimer); firstByteTimer = null; }

	// 统一出口：根据是否有数据决定关闭 WS 还是重试
	if (retryTriggered) {
		// timeout 已触发 retry，不做额外处理
		return;
	}
	if (hasIncoming) {
		log && log("data transfer complete, closing WebSocket");
		safeCloseWebSocket(ws);
	} else if (retry) {
		log && log("no data from remote, retrying via proxy");
		retry();
	} else {
		log && log("no data and no retry available, closing WebSocket");
		safeCloseWebSocket(ws);
	}
}

/* ---------- 单次拨号：走官方 cloudflare:sockets 的 connect，带超时 ---------- */
// 注意：不要换成 request.fetcher.connect（GrainTCP 灰接口）——那个接口会拒绝 IPv6 目标，
// 报 "cannot connect to the specified address"，表现为所有 IPv6 站点都直连失败。
async function dialWithTimeout(host, port, timeoutMs) {
	const socket = connect({ hostname: host, port });
	let timer = null;
	try {
		await Promise.race([
			socket.opened,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(`dial timeout ${timeoutMs}ms`)), timeoutMs);
			})
		]);
		return socket;
	} catch (e) {
		// 超时后底层可能仍在建连，等它落地就立刻关掉，避免连接泄漏
		socket.opened.then(() => { try { socket.close(); } catch (_) { } }, () => { });
		throw e;
	} finally {
		if (timer) clearTimeout(timer);
	}
}

/* ---------- 并发拨号：多路同时建连，取最先打开的那条 ---------- */
async function dialFastest(host, port, attempts, log) {
	if (!(attempts > 1)) return dialWithTimeout(host, port, DIAL_TIMEOUT);
	// dialWithTimeout 是 async，同步抛错（地址非法等）会自动变成 rejected promise，交给 Promise.any 统一处理
	const pendingDials = Array.from({ length: attempts }, () => dialWithTimeout(host, port, DIAL_TIMEOUT));
	// 落败分支的 rejection 要先接住，否则会变成未处理的 rejection
	pendingDials.forEach((p) => p.catch(() => { }));
	try {
		const winner = await Promise.any(pendingDials);
		pendingDials.forEach((p) => p.then((s) => {
			if (s !== winner) { try { s.close(); } catch (_) { } }
		}, () => { }));
		log(`dial race ${attempts} 路 → ${host}:${port}`);
		return winner;
	} catch (e) {
		throw (e instanceof AggregateError && e.errors.length) ? e.errors[0] : e;
	}
}

/* ---------- 建立 TCP 连接（或走代理） ---------- */
async function handleTCPOutBound(headerInfo, io) {
	const { proxyInfo, ws, log, serialUplink, dialAttempts, attachSocket, drainUplink, makeDownlinkGuard, onFirstDownlink, sendResponseHeaderOnce } = io;

	// 在串行链内建连并挂载；挂载会把未确认数据标成待重发，随后由排空循环写到新连接上
	async function dialAndAttach(host, port, attempts) {
		return serialUplink(async () => {
			const tcp = await dialFastest(host, port, attempts, log);
			attachSocket(tcp);
			log(`connected to ${host}:${port}`);
			return tcp;
		});
	}

	// 只有当前世代的连接才有资格补响应头、标记确认；旧 socket 迟到的数据一律忽略
	const firstDownlinkOf = (guard) => () => {
		if (guard()) onFirstDownlink();
	};

	// 代理重试：直连握手失败、或直连后首字节超时，都走 ProxyIP，最多 3 次
	let retryRemaining = 3;
	async function retry() {
		if (!proxyInfo || retryRemaining <= 0) return;
		retryRemaining--;
		log(`retry ${3 - retryRemaining}/3 via proxy ${proxyInfo.hostname}:${headerInfo?.portRemote}`);
		try {
			const tcp = await dialAndAttach(proxyInfo.hostname, headerInfo?.portRemote, 1);
			// 连接已建立：立刻回 VLESS 响应头，不等客户端先给数据
			sendResponseHeaderOnce();
			drainUplink();
			const guard = makeDownlinkGuard();
			// 还有剩余重试次数则继续传递 retry，否则传 null 停止重试
			relayDownlink(tcp, ws, retryRemaining > 0 ? retry : null, log, guard, firstDownlinkOf(guard));
		} catch (err) {
			// 代理 TCP 握手也失败，继续尝试下一次重试
			log(`proxy connect failed: ${err.message}, retries left: ${retryRemaining}`);
			if (retryRemaining > 0) await retry();
			else safeCloseWebSocket(ws);
		}
	}

	// 1、先尝试直连（多路竞速）
	try {
		const tcp = await dialAndAttach(headerInfo?.addressRemote, headerInfo?.portRemote, dialAttempts);
		// 连接已建立：立刻回 VLESS 响应头，不等客户端先给数据
		sendResponseHeaderOnce();
		drainUplink();
		// 2、再把读写流桥接（直连无数据时触发 retry）
		const guard = makeDownlinkGuard();
		relayDownlink(tcp, ws, retry, log, guard, firstDownlinkOf(guard));
	} catch (err) {
		// 直连 TCP 握手失败（SYN 被封锁等），直接走代理重试
		log(`direct connect failed: ${err.message}, retrying via proxy`);
		await retry();
	}
}

/* ---------- UDP DNS 代理（端口 53 → DoH） ---------- */
async function handleUDPOutBound(webSocket, responseHeader, log) {
	let isHeaderSent = false;
	let buffer = new Uint8Array(0);

	const transformStream = new TransformStream({
		transform(chunk, controller) {
			// 将新 chunk 追加到 buffer
			const newBuf = new Uint8Array(buffer.byteLength + chunk.byteLength);
			newBuf.set(buffer, 0);
			newBuf.set(new Uint8Array(chunk), buffer.byteLength);
			buffer = newBuf;

			// 循环提取完整的 UDP 包：[2字节长度][数据]
			while (buffer.byteLength >= 2) {
				const udpPacketLength = new DataView(buffer.buffer, buffer.byteOffset, 2).getUint16(0);
				if (buffer.byteLength < 2 + udpPacketLength) {
					break; // 数据不完整，等待下一个 chunk
				}
				const udpData = new Uint8Array(buffer.slice(2, 2 + udpPacketLength));
				controller.enqueue(udpData);
				buffer = buffer.slice(2 + udpPacketLength);
			}
		},
	});

	// 只处理 DNS UDP（端口 53）
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(DOH_SERVER, {
				method: 'POST',
				headers: { 'content-type': 'application/dns-message' },
				body: chunk,
			});
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error);
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 * @param {Uint8Array} chunk
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/* ---------- 安全关闭 WebSocket ---------- */
function safeCloseWebSocket(ws, code = 1000, reason = "Normal Closure") {
	try {
		if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING) {
			ws.close(code, reason);
		}
	} catch (e) {
		console.error("Failed to close WebSocket", e);
	}
}

/* ------------------- Durable Object 本体 ------------------- */
export class WsDo extends DurableObject {
	/**
	 * @param {DurableObjectState} state
	 * @param {{PYIP?:string, UUID4?:string, TCP_CONCURRENT_DIAL?:string|number}} env
	 */
	constructor(state, env) {
		super(state, env);
		this.state = state;
		this.proxyAddress = env.PYIP ?? "";
		this.uuid4 = env.UUID4 ?? DEFAULT_UUID;
		this.userIDUint8Array = userIdToUint8Array(this.uuid4);
		this.dialAttempts = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || CONCURRENT_DIALS);
		// 实例创建是「首次访问慢」的一个候选原因：和同一个请求的 fetch 日志对时间戳就能看出来
		console.log(`[do] instance constructed ${new Date().toISOString()}`);
	}

	/**
	 * @param {Request} request
	 * @returns {Promise<Response>}
	 */
	async fetch(request) {
		// ----------------- 非 WebSocket 请求：一律给 nginx 伪装页 ----------
		if (!isWebSocketUpgrade(request)) {
			return nginxResponse(new URL(request.url));
		}

		// ----------------- 读取运行时配置 -----------------
		const userIDUint8Array = this.userIDUint8Array;


		const hostPort = splitHostPort(this.proxyAddress);
		const proxyInfo = hostPort.host ? { hostname: hostPort.host, port: hostPort.port } : null;

		// ----------------- 真实的 WebSocket 处理 -----------------
		const [clientSide, serverSide] = Object.values(new WebSocketPair());
		// allowHalfOpen：一端结束时不要连带关掉另一端，隧道两端的结束时机常常不一致
		try { serverSide.accept({ allowHalfOpen: true }); } catch (_) { serverSide.accept(); }

		// 日志统一函数：带「距本次 fetch 进入」的相对毫秒，方便把首次连接的分段耗时看成一整条时间线
		const fetchStartedAt = Date.now();
		let address = "";
		let portLog = "";
		const log = (msg, data) => console.log(`[${address}${portLog}] +${Date.now() - fetchStartedAt}ms ${msg}`, data || "");

		// ---------- 将浏览器→DO 的数据转成可读流 ----------
		const uplinkQueue = { bytes: 0 };
		const earlyProtoHeader = request.headers.get("sec-websocket-protocol") || "";
		const inbound = makeReadableWebSocketStream(serverSide, earlyProtoHeader, log, uplinkQueue);

		// ---------- 用一个 wrapper 保存 "远程 TCP socket" ----------
		const remoteSocketWrapper = { value: null };
		let udpWrite = null;
		let isDns = false;

		// ---------- 上行：合包队列 + 重放 ----------
		// queue[i]（i < written）已经写进当前 socket，i >= written 还没写。
		// keepWritten = true 时这些数据留着给切连接时重发；远端回包或缓冲超限后就不再保留。
		const uplink = { queue: [], written: 0, bytes: 0, keepWritten: true, confirmed: false };
		const dialAttempts = this.dialAttempts;
		let currentWriter = null;
		let draining = false;
		let drainScheduled = false;
		let uplinkPackBuffer = null;
		let downlinkGen = 0;
		let uplinkChain = Promise.resolve();

		// 所有上行写入串行化：保证「切到新 socket」和正在进行的写入不会交错，避免重放丢数据或重复发送
		const serialUplink = (task) => {
			const result = uplinkChain.then(task);
			uplinkChain = result.then(() => { }, () => { });
			return result;
		};

		const releaseWriter = () => {
			try { currentWriter && currentWriter.releaseLock(); } catch (_) { }
			currentWriter = null;
		};

		// 丢掉「已写进 socket」的前缀，只保留还没写出去的部分
		const dropWrittenPrefix = () => {
			if (uplink.written === 0) return;
			// 逐条扣减，避免每次都对整条队列 reduce 一遍
			for (let i = 0; i < uplink.written; i++) uplink.bytes -= uplink.queue[i]?.byteLength || 0;
			uplink.queue.splice(0, uplink.written);
			uplink.written = 0;
		};

		// WS 二进制消息给的是 ArrayBuffer；统一存成视图。
		// 注意：TypedArray.set(ArrayBuffer, offset) 会静默拷贝 0 字节（ArrayBuffer 不是 array-like），
		// 直接拿原始 ArrayBuffer 去 set/合包会把整段数据写成零。
		const toView = (chunk) => {
			if (chunk instanceof Uint8Array) return chunk;
			if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
			if (ArrayBuffer.isView(chunk)) return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
			return null;
		};

		const recordUplink = (chunk) => {
			const view = toView(chunk);
			const length = view?.byteLength ?? 0;
			if (!length) return;
			uplink.queue.push(view);
			uplink.bytes += length;
			if (uplink.keepWritten && uplink.bytes > UPLINK_REPLAY_LIMIT) {
				uplink.keepWritten = false;
				log(`上行缓冲超限（>${UPLINK_REPLAY_LIMIT}B），放弃重放`);
				serialUplink(() => dropWrittenPrefix()).catch(() => { });
			}
		};

		// 从 written 起把连续小块并成一次写入
		const takeUplinkBatch = () => {
			const start = uplink.written;
			const first = uplink.queue[start];
			if (!first) return null;
			let length = first.byteLength, j = start + 1;
			while (j < uplink.queue.length && length < UPLINK_PACK_TARGET) {
				const total = length + uplink.queue[j].byteLength;
				if (total > UPLINK_PACK_TARGET) break;
				length = total;
				j++;
			}
			const count = j - start;
			if (count === 1) return { data: first, count };
			// 合并缓冲固定复用：写入是 await 的，写完才可能被下一批覆盖
			const merged = uplinkPackBuffer ||= new Uint8Array(UPLINK_PACK_TARGET);
			let offset = 0;
			for (let i = start; i < j; i++) {
				merged.set(uplink.queue[i], offset);
				offset += uplink.queue[i].byteLength;
			}
			return { data: merged.subarray(0, length), count };
		};

		const drainUplink = () => {
			if (draining || drainScheduled) return;
			drainScheduled = true;
			// 先让出一个任务再开始排空：同一批到达的多个 WS 帧会在这期间入队，从而并进同一次写入。
			// 代价是每个上行突发多一个事件循环轮次（远小于下行门控最多 4ms 的观察窗口），
			// 换来的是突发小包从"每条一次 write"变成"整批一次 write"。
			setTimeout(() => {
				drainScheduled = false;
				if (draining) return;
				draining = true;
				serialUplink(async () => {
					try {
						while (currentWriter && uplink.written < uplink.queue.length) {
							const batch = takeUplinkBatch();
							if (!batch) break;
							await currentWriter.write(batch.data);
							uplink.written += batch.count;
							// 写完再让出一轮，给后续小块一个并进下一批的机会
							if (uplink.written < uplink.queue.length) await Promise.resolve();
						}
						if (!uplink.keepWritten) dropWrittenPrefix();
					} catch (e) {
						log(`uplink write error: ${e?.message || e}`);
						releaseWriter();
					}
				}).catch(() => { }).finally(() => {
					draining = false;
					// 排空期间又到了新数据
					if (currentWriter && uplink.written < uplink.queue.length) drainUplink();
				});
			});
		};

		// 切到新连接：换写入器、让旧下行泵立刻失效、把未丢弃的数据全部标成待重发
		const attachSocket = (socket) => {
			remoteSocketWrapper.value = socket;
			releaseWriter();
			currentWriter = socket.writable.getWriter();
			uplink.written = 0;
			downlinkGen++;
		};

		// 远端回包说明这条连接可用：不再保留重放数据
		const markConfirmed = () => {
			if (uplink.confirmed) return;
			uplink.confirmed = true;
			uplink.keepWritten = false;
			serialUplink(() => dropWrittenPrefix()).catch(() => { });
		};

		// 下行守卫：切连接时世代自增，旧 socket 迟到的数据不会再写进 WS
		const makeDownlinkGuard = () => {
			const gen = downlinkGen;
			return () => downlinkGen === gen && serverSide.readyState === WS_READY_STATE_OPEN;
		};

		// 响应头的发送时机受两条约束夹着：
		// 1) 不能在解析首包时立刻发。开了 early data 的客户端，首包是在 makeReadableWebSocketStream
		//    的 start() 里就进管道的，那次写入可能早于 DO 的 101 送达客户端，帧在真实边缘有概率被丢掉
		//    （客户端就会把第一个载荷字节当成版本号读）。
		// 2) 也不能等首条下行数据再发。VLESS 客户端（sing-box）会在建连流程里同步等响应头，拿到才把
		//    业务数据发出来；而首包没有载荷（没 sniff 到数据）时，两边就互等，3.5 秒后首字节超时切
		//    PYIP，浏览器侧看到的是 TLS 握手中途失败。
		// 所以：目标连接建立后立刻发 —— 一次拨号至少一个 RTT，那时 101 必然已送达；且不依赖客户端先给数据。
		let responseHeader = null;
		let responseHeaderSent = false;
		const sendResponseHeaderOnce = () => {
			if (responseHeaderSent || !responseHeader) return;
			responseHeaderSent = true;
			if (serverSide.readyState === WS_READY_STATE_OPEN) serverSide.send(responseHeader);
		};

		// 远端回包说明这条连接可用：释放重放数据。响应头在建连后已经发过了（幂等兜底一次）。
		const onFirstDownlink = () => {
			log("first downlink byte");
			sendResponseHeaderOnce();
			markConfirmed();
		};

		const io = {
			proxyInfo,
			ws: serverSide,
			log,
			dialAttempts,
			serialUplink,
			attachSocket,
			drainUplink,
			makeDownlinkGuard,
			onFirstDownlink,
			sendResponseHeaderOnce,
		};

		// ---------- 把 inbound 流 pipe 到处理函数 ----------
		inbound
			.pipeTo(
				new WritableStream({
					async write(chunk, controller) {
						uplinkQueue.bytes -= (chunk?.byteLength ?? 0);
						// DNS UDP 已建立，直接转发 DNS 数据
						if (isDns && udpWrite) {
							return udpWrite(chunk);
						}
						// TCP 连接已建立（或正在重连）：进合包队列，由排空循环写出去
						if (remoteSocketWrapper.value) {
							recordUplink(chunk);
							drainUplink();
							return;
						}

						// ----- 解析协议头，得到目标地址、端口、以及原始客户端数据 -----
						let headerInfo = parseProtocolHeader(chunk, userIDUint8Array);
						if (!headerInfo || headerInfo?.hasError) {
							throw new Error(`header parse error: ${headerInfo?.message}`);
						}

						address = headerInfo?.addressRemote;
						portLog = `-${(Math.random().toString(36) + "000000").slice(2, 8)} ${headerInfo?.isUDP ? 'udp' : 'tcp'}`;

						// UDP 仅允许端口 53（DNS）
						if (headerInfo?.isUDP) {
							if (headerInfo?.portRemote === 53) {
								isDns = true;
								const { write } = await handleUDPOutBound(serverSide, headerInfo?.responseHeader, log);
								udpWrite = write;
								udpWrite(headerInfo?.rawClientData);
								return;
							} else {
								throw new Error("UDP proxy only enable for DNS which is port 53");
							}
						}

						// ----- TCP：响应头在目标连接建立后由 handleTCPOutBound 发出（原因见 sendResponseHeaderOnce 的注释）-----
						// UDP 分支由 handleUDPOutBound 自己带响应头，不走这里
						responseHeader = headerInfo.responseHeader;

						// 首包之后的数据进合包队列，直连失败/超时切代理时会被重发
						recordUplink(headerInfo?.rawClientData);
						await handleTCPOutBound(headerInfo, io);
					},
					close() {
						log("inbound stream closed");
					},
					abort(reason) {
						log("inbound stream aborted", reason);
					},
				})
			)
			.catch((e) => {
				log("inbound pipe error", e);
			});

		// 最终把 clientSide 交给浏览器
		// 显式置空 Sec-WebSocket-Extensions：隧道里本来就是密文，再协商 permessage-deflate 只是白烧 CPU
		return new Response(null, { status: 101, webSocket: clientSide, headers: { 'Sec-WebSocket-Extensions': '' } });
	}
}

/* ---------- DO 实例 id：固定 id + 分片 + locationHint ---------- */
const DEFAULT_UUID = "c3deb827-585e-4137-98a4-2dd4058f9836";

// 分片数为 1 时保持原来的 id 不变，已有部署升级后不会换 DO 实例、出口 IP 不会变
// 分片数 > 1 时每条连接随机挑一个分片：并发连接摊到多个实例上，避免单实例单线程成为瓶颈
function instanceName(location, uuid, shards) {
	const base = `user-${location}-${uuid ?? DEFAULT_UUID}`;
	if (shards <= 1) return base;
	return `${base}-${Math.floor(Math.random() * shards)}`;
}

export default {
	/**
	 * @param {Request} request
	 * @param {{PYIP?:string, UUID4?:string, REGION?:string, DO_SHARDS?:string|number, WS_DO: DurableObjectNamespace}} env
	 * @param {ExecutionContext} ctx
	 */
	async fetch(request, env, ctx) {
		// --------- 非 WebSocket 请求：一律给 nginx 伪装页 ----------
		if (!isWebSocketUpgrade(request)) {
			return nginxResponse(new URL(request.url));
		}

		// --------- WebSocket 请求：把完整 Request 转发给 Durable Object ----------
		// https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1
		// https://where.durableobjects.live/
		// 可选：["wnam", "enam", "sam", "weur", "eeur", "apac", "oc", "afr", "me"]
		const doLocation = env.REGION || "wnam";
		// 固定 id + locationHint 保证同一分片内的出口 IP 稳定；DO_SHARDS > 1 时每条连接随机挑分片，
		// 把并发连接摊到多个 DO 实例上（默认 1，等价于原来的单实例行为）
		const shards = Math.max(1, Math.floor(Number(env.DO_SHARDS)) || 1);
		const name = instanceName(doLocation, env.UUID4, shards);
		const id = env.WS_DO.idFromName(name);
		const stub = env.WS_DO.get(id, { locationHint: doLocation });

		// Worker 侧也留一条：和 DO 的日志对不上时，能立刻区分「没转发」还是「DO 日志没显示」
		const forwardStartedAt = Date.now();
		const response = await stub.fetch(request);
		console.log(`[worker] ws → ${name} 耗时 ${Date.now() - forwardStartedAt}ms`);
		return response;
	},
};

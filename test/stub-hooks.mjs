// 把 Workers 专有模块替换成测试桩，便于在 Node 里直接跑 src/index.js
export async function resolve(specifier, context, nextResolve) {
	if (specifier === 'cloudflare:sockets') return { url: 'stub:sockets', shortCircuit: true };
	if (specifier === 'cloudflare:workers') return { url: 'stub:workers', shortCircuit: true };
	return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
	if (url === 'stub:sockets') {
		return {
			format: 'module',
			shortCircuit: true,
			source: `
				export function connect(address, options) {
					const stub = globalThis.__socketStub;
					if (!stub || !stub.handler) throw new Error('测试未设置 connect handler');
					stub.calls.push(address);
					return stub.handler(address, options);
				}
			`
		};
	}
	if (url === 'stub:workers') {
		return {
			format: 'module',
			shortCircuit: true,
			source: `
				export class DurableObject {
					constructor(state, env) { this.ctx = state; this.env = env; }
				}
			`
		};
	}
	return nextLoad(url, context);
}

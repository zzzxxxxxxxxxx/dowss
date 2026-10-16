# dowss

基于 cf worker Durable Object 的 CF 隧道，一旦在指定的地区创建DO实例，IP 地址就稳定下来，几乎不会变，要变也变动很小(变动，可能你长时间没有使用，不活跃而自动销毁，重新连接调剂到隔壁IP)，只变IPv4最后一段数字。

## 一、关于部署

- 使用 Wrangler CLI 部署

  先将全部代码下载或git clone命令下载到本地电脑中，然后：

```
# 安装依赖
npm install

# 登录你的cloudflare账号
npx wrangler login

# 部署到cloudflare workers中
wrangler deploy
```

- 其他部署途径，没有尝试过。

- 必须是 Workers 形态：本项目依赖 Durable Object 绑定，因此不能作为 Cloudflare Snippets 运行
  （Snippets 是 zone 级的 Rules 功能，没有绑定机制，执行时限也只有 5ms）。

## 二、修改变量

可以先部署，再到CF后台修改**变量和机密**。也可以部署前找到 `wrangler.toml` 里面 `[vars]` 字段，修改里面的字段值。

| 名称   | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| PYIP   | PROXYIP 回退代理地址，直连失败时通过此 IP 中转。端口由目标地址决定，此处只需填 IP |
| UUID4  | vless协议的userId                                            |
| REGION | DO 放置区域，第一次部署实例化才生效，可选：wnam/enam/sam/weur/eeur/apac/oc/afr/me |
| DO_SHARDS | DO 分片数，默认 `1`。`1` 时所有连接共用一个实例（出口 IP 最稳、duration 计费最省）；`>1` 时每条连接随机挑一个分片，把并发连接摊到多个实例上——各分片仍在同一区域，但不同连接可能落在不同实例。注意：分片数会成倍消耗 DO duration 额度；从 `1` 改成 `>1`（或改回来）会换用新的实例名 |
| TCP_CONCURRENT_DIAL | 直连并发拨号数，默认 `2`：同时发起多路 TCP 建连，取最先建立的一条，用来吃掉 CF 路由层的抖动。设为 `1` 可关闭竞速（每请求的同时打开连接数有配额，2 路只占其中一部分，默认值是安全的；调大则要留意这个配额） |

## 三、注意：

### 1、Durable Object 免费额度：

- 无服务器计算和 SQL 数据库
- 每天最多 100,000 个请求
- 每天最多 13,000 GB-秒持续时间
- 每天最多 5 百万次行读取
- 每天最多 100,000 次行写入
- 含 5GB 存储

这个要注意：特别是**每天最多 100,000 个请求** 和**每天最多 13,000 GB-秒持续时间** 。

### 2、换其他地区要注意的坑：

```
const stub = env.WS_DO.get(id, {locationHint: "wnam"});
```

locationHint 只在“第一次实例化”时被 Cloudflare 使用。之后的所有 get()（即使带不同的 hint）都忽略这个参数，只把请求路由到已经绑定好的节点。

```
const id = env.WS_DO.idFromName(name);
```

可以尝试改变name字符串，有概率变成wnam大区下面的其它城市。

还有一种方法，将DO放置到 eu (欧盟地区) 和 fedramp (好像是放置到美国本地大陆)，它优先于 locationHint。

```
const id = env.WS_DO.jurisdiction("eu").idFromName(name);
const id = env.WS_DO.jurisdiction("fedramp").idFromName(name);
```

设置了jurisdiction，后面的 locationHint 参数忽略。

最后，网速OK情况，就不要乱动，可能改得速度更慢，要删掉重新部署，还可能重新部署也慢，要等一天重新部署才恢复。

以上，经这几天测试的经验之谈，不保证就是唯一真理。

### 3、部署后，使用发现网速比较慢

开始使用是比较慢的，慢慢会提升速度，如果用了很久，速度还是没有提升，就是DO放置的位置不合适。特别是多次更改位置部署的，很大概率变慢的。

### 4、部署位置可参考： [link](https://where.durableobjects.live/)

### 5、TCP 出站用的是 request 级 fetcher

代码不 `import { connect } from "cloudflare:sockets"`，而是用 `request.fetcher.connect()`——这是 GrainTCP 引入的
request 级灰接口，未见于官方 API 文档。运行时会给每个入口请求挂上这个 fetcher，DO 里同样有（本地 e2e 已实测：
下行 4MB、上行 16MB 字节一致，重试链连 PYIP 也正常）。这样做的收益是源码里少一个明显的特征串。

万一哪天部署后报 `request.fetcher.connect unavailable`，说明运行时不再提供这个接口：
把 `dialWithTimeout()` 里的 `fetcher.connect({ hostname, port })` 换回
`import { connect } from "cloudflare:sockets"` 的 `connect({ hostname, port })`，并把 `dialFastest` / `handleTCPOutBound`
上多出来的 `fetcher` 参数一起去掉即可。

## 四、回归测试

隧道数据路径（上行合包、下行 BYOB 大包直发与小包聚合、切代理时重放、下行世代隔离）有一份 Node 挂具：

```
node test/tunnel.test.mjs
```

不需要 wrangler、不需要部署。它用桩顶替 `cloudflare:sockets` 与 `cloudflare:workers`，直接在 Node 里跑 `src/index.js`，
用假 socket 喂数据验证字节顺序、合包次数和重放完整性。改了 `src/index.js` 的数据路径后先跑这个再部署。

### 本地端到端（wrangler dev + xray-core）

需要本机有 `wrangler`、`xray`、`python3`、`curl`。开三个终端：

```
# 1) 本地 worker（DO 与变量都用 wrangler.toml 里的值）
wrangler dev --port 8787 --ip 127.0.0.1

# 2) 测试源站：GET /payload 返回 4MB 随机数据，POST /echo 回显 body 的 sha256
python3 test/e2e/origin.py 18000

# 3) xray 客户端：SOCKS 127.0.0.1:10808 → VLESS/WS → 本地 worker（已开 early data）
xray run -c test/e2e/xray-client.json
```

然后比对直连与过隧道的哈希，三者必须一致：

```
curl -sS -o /tmp/d.bin http://127.0.0.1:18000/payload && sha256sum /tmp/d.bin
curl -sS --socks5-hostname 127.0.0.1:10808 -o /tmp/p.bin http://127.0.0.1:18000/payload && sha256sum /tmp/p.bin
curl -sS -X POST --socks5-hostname 127.0.0.1:10808 --data-binary @<任意文件> http://127.0.0.1:18000/echo
```

想验重试链（直连不回包 → 切 PYIP → 重放）就再起 `python3 test/e2e/silent.py`，
访问 `http://127.0.0.1:18001/`，worker 日志里应出现 `no data within 3500ms, triggering retry` 与 `retry N/3 via proxy ...`，
且全程没有 ERROR。

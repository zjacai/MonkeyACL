# Monkey ACL

![License](https://img.shields.io/badge/License-MIT-blue)
![Author](https://img.shields.io/badge/Scorcsoft-8A2BE2)
![Firewall Manage](https://img.shields.io/badge/Firewall%20Manage-00BA98)

## 🚀 简介


<p align="center">
  <img src="images/start.png" width="100%"/>
</p>

**Monkey ACL (吗喽ACL)** 是一款基于 HTTP API 的防火墙动态授权管理工具，帮助你安全、高效、智能地管理服务器远程访问权限。

---

### 💡 适用场景

- 持有云服务器，需要远程管理（SSH / RDP），不得不对公网开放端口。
- 面对暴力破解、扫描器等 7×24 小时攻击风险。
- 云厂商安全组配置繁琐，手动操作效率低，还需针对不同云平台开发多套工具。

👉 **Monkey ACL 用一套统一方案，帮你彻底解决这些难题！**

---

## 🌟 特性亮点

✅ **简单易用** — 纯 Python 3 标准库，无需任何第三方依赖。  
✅ **零配置启动** — 单文件运行，参数即配置。  
✅ **动态授权** — API 调用即授权当前 IP 临时访问指定端口。  
✅ **自动回收** — 无需手动清理，失效规则智能移除。  
✅ **跨平台** — 自动识别 Linux（firewalld / ufw / iptables / nftables）与 Windows Firewall。  
✅ **自动证书** — 未提供 SSL 证书时自动签发自签名证书并启用 HTTPS。  
✅ **平台无关** — 本地防火墙控制，无需依赖云平台 API。  
✅ **高度可集成** — 适配 iPhone Shortcuts、自动化脚本等工具，实现极简体验。

---

## ⚡ 快速开始

### 1️⃣ 克隆项目
```bash
git clone https://github.com/Scorcsoft/MonkeyACL.git
cd MonkeyACL
```

### 2️⃣ SSL 证书（可选）
API 服务始终使用 HTTPS。未传入 `--cert` / `--key` 时，程序会自动生成自签名证书（`monkeyacl-auto.pem` / `monkeyacl-auto.key`）并直接使用。

也可以自行提供证书：购买商用证书、用 Let's Encrypt 签发，或本地生成：

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

自签名证书调用 API 时请使用 `curl -k`。

### 3️⃣ 启动参数

| 参数 | 必填 | 说明 |
|------|------|------|
| `--auth` | 是 | API 访问密钥。长度必须大于 16，且同时包含大写字母、小写字母和数字 |
| `--port` | 是 | API 服务监听端口，请确保云安全组和本机防火墙已放通此端口 |
| `--url` | 是 | API 路径，建议使用随机字符串，避免被扫描到 |
| `--cert` | 否 | SSL 证书文件路径，pem 格式。需与 `--key` 一起提供 |
| `--key` | 否 | SSL 私钥文件路径，pem 格式。需与 `--cert` 一起提供 |
| `--interval` | 否 | 空闲检测间隔，单位秒，默认 `600`（10 分钟）。该 IP 断开后，经过此间隔会被回收 |
| `-h` / `--help` | 否 | 显示帮助信息 |

Linux 需要 root，Windows 需要以管理员身份运行。Windows CMD 下参数不要包单引号。

### 4️⃣ Linux 启动

```bash
sudo python3 monkeyACL.py --auth=Geh8uwAbcdefg123 --port=23456 --url=vefhuwbyuvftyuvwegfyugvy
```

指定已有证书：

```bash
sudo python3 monkeyACL.py --auth=Geh8uwAbcdefg123 --port=23456 --url=vefhuwbyuvftyuvwegfyugvy --cert=cert.pem --key=key.pem
```

### 5️⃣ Windows 启动

管理员 CMD / PowerShell：

```bat
python monkeyACL.py --auth=Geh8uwAbcdefg123 --port=23456 --url=vefhuwbyuvftyuvwegfyugvy
```

指定已有证书：

```bat
python monkeyACL.py --auth=Geh8uwAbcdefg123 --port=23456 --url=vefhuwbyuvftyuvwegfyugvy --cert=cert.pem --key=key.pem
```

启动成功示例：
```text
[i] Firewall backend: windows
[i] MonkeyACL is running at: https://0.0.0.0:23456/vefhuwbyuvftyuvwegfyugvy
[i] Using a self-signed SSL certificate. Call the API with curl -k.
[i] If you cannot access the Monkey ACL API service, open the API port:
netsh advfirewall firewall add rule name="MonkeyACL-API" dir=in action=allow protocol=TCP localport=23456
```

---

## 🔑 调用 API 加白

请求方式：`POST`  
地址：`https://<服务器IP>:<API端口>/<url>`  
Body：JSON

| 字段 | 必填 | 说明 |
|------|------|------|
| `auth` | 是 | 与启动参数 `--auth` 相同的密钥 |
| `action` | 否 | `add` 加白（默认），`delete` 删除该 IP 的全部 Monkey ACL 规则 |
| `port` | 加白时必填 | 要放行的业务端口，例如 `3389`、`22`、`8080` |
| `protocol` | 加白时必填 | `tcp` 或 `udp` |
| `ip` | 否 | 目标 IPv4。不传则使用本次请求的来源 IP |
| `ttl` | 否 | 加白有效秒数。到期后即使仍在连接也会删除。不传则仅在断开后自动回收 |

新规则有 3 分钟宽限期，被授权 IP 需在宽限期内连上服务器，超时未连接会被自动回收。

### Linux 调用示例

放行当前设备访问 3389：

```bash
curl -X POST -k -d '{"auth":"Geh8uwAbcdefg123","port":3389,"protocol":"tcp"}' "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

给指定 IP 临时加白：

```bash
curl -X POST -k -d '{"auth":"Geh8uwAbcdefg123","port":3389,"protocol":"tcp","ip":"203.0.113.10"}' "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

### Windows 调用示例

CMD / PowerShell 使用 `curl.exe`，JSON 内的双引号需要转义：

放行当前设备访问 3389：

```bat
curl.exe -X POST -k -d "{\"auth\":\"Geh8uwAbcdefg123\",\"port\":3389,\"protocol\":\"tcp\"}" "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

给指定 IP 临时加白：

```bat
curl.exe -X POST -k -d "{\"auth\":\"Geh8uwAbcdefg123\",\"port\":3389,\"protocol\":\"tcp\",\"ip\":\"203.0.113.10\"}" "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

成功响应：
```json
{"success": true, "message": "Create firewall rule success: 203.0.113.10 --[tcp]--> 3389", "ip": "203.0.113.10", "action": "add"}
```

---

## 🧹 删除白名单

### 自动回收
默认每隔 10 分钟检测一次：该 IP 当前没有连接到服务器时，规则自动删除。启动时可用 `--interval` 调整，例如 `--interval=1800` 为 30 分钟。加白后有 3 分钟宽限期，避免对方还没连上就被清掉。

### 到期删除
加白时带 `ttl`（秒）。到期后即使还连着也会删除。

Linux：

```bash
curl -X POST -k -d '{"auth":"Geh8uwAbcdefg123","port":3389,"protocol":"tcp","ip":"203.0.113.10","ttl":3600}' "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

Windows：

```bat
curl.exe -X POST -k -d "{\"auth\":\"Geh8uwAbcdefg123\",\"port\":3389,\"protocol\":\"tcp\",\"ip\":\"203.0.113.10\",\"ttl\":3600}" "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

### 立即删除
`action` 设为 `delete`。不传 `ip` 时删除本次请求来源 IP 的规则。

Linux：

```bash
curl -X POST -k -d '{"auth":"Geh8uwAbcdefg123","action":"delete","ip":"203.0.113.10"}' "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

Windows：

```bat
curl.exe -X POST -k -d "{\"auth\":\"Geh8uwAbcdefg123\",\"action\":\"delete\",\"ip\":\"203.0.113.10\"}" "https://your_server_ip:23456/vefhuwbyuvftyuvwegfyugvy"
```

---

## 🕒 自动回收机制

👉 Monkey ACL 默认每隔 **10 分钟** 检测一次已授权 IP 的连接状态，可用 `--interval` 调整。  
👉 **当某 IP 当前没有连接到服务器时，临时授权自动撤销。保障服务器端口最小暴露，无需人工干预。**  



```TEXT

[2025-06-20 17:48:56] The authorized IP: [180.184.***.***] is not connected to this server, its permission will be removed.
[2025-06-20 17:48:58] Successfully removed access permission for [180.***.***.***]

```

如果该设备需要再次访问服务器，请重新访问获取临时授权 API

---

## 📱 iPhone 联动

### 使用 iPhone 快捷指令自动授权，无需每次手动访问

### 1️⃣ 创建快捷指令
打开 iPhone 的快捷指令 app，点击右上角 + 号新建一个快捷指令：

创建以下快捷指令：

<p align="center">
  <img src="images/iPhone-1.png" width="30%"/>
</p>

### 2️⃣ 配置快捷指令自动运行

**切换到”自动化“界面**

<p align="center">
  <img src="images/iPhone-3.jpg" width="30%"/>
</p>

**创建自动化**

单击右上角 + 号，创建一个自动化条件：

<p align="center">
  <img src="images/iPhone-4.png" width="30%"/>
</p>

**选择 APP**

选择需要服务器访问权限的APP，例如：你的远程桌面客户端或 SSH 客户端

<p align="center">
  <img src="images/iPhone-5.jpg" width="30%"/>
</p>

**修改运行配置**

将该自动化配置为”立即运行“

<p align="center">
  <img src="images/iPhone-7.jpg" width="30%"/>
</p>


### 3️⃣ 完成

打开该 App，iPhone 的快捷指令会在 App 打开时执行设定的快捷执行，访问 Monkey ACL 的 API 将你手机当前的 IP 地址添加到防火墙规则。

<p align="center">
  <img src="images/iPhone-8.png" width="30%"/>
</p>


## 📱 Android 联动

我没有 Android 手机，不知道各安卓设备有没有类似快捷指令的 App。尊贵的 Android 用户可以使用浏览器手动访问 API。

---

## 🛠 故障排查

### 访问 API 后设备仍然无法访问？
✅ 检查云平台安全组是否已放通目标端口。  
✅ 确认 API 服务端口在云平台和本机防火墙中均已开放。  
✅ 注意：Monkey ACL 仅管理本地防火墙，不会修改云安全组配置。

---

## 📄 License

MIT

---

## 🤝 欢迎贡献

欢迎提交 Issue 或 PR，共同完善和优化 Monkey ACL！
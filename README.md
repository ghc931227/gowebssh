### fork from github.com/leffss/gowebssh
### add proxy support, and management of ssh connection

## 使用说明

```
gowebssh.exe [-p 端口] [-auth user:password] [-cert 证书 -key 私钥] [-audit 审计目录]
```

| 参数 | 说明 |
|---|---|
| `-p` | 监听端口，默认 `2223` |
| `-auth` | HTTP Basic 认证，格式 `user:password`。**不设置则不需要登录**；设置后所有页面与接口都需要登录 |
| `-tabs` | 启用浏览器内多标签会话（默认关闭：同一页面仅一个会话，新连接替换旧会话） |
| `-cert` / `-key` | TLS 证书与私钥，两者同时设置后启用 HTTPS |
| `-audit` | 会话审计记录目录，默认 `sessions`（终端输出逐会话记录到该目录，设为空字符串 `-audit=` 关闭） |
| `-session-ttl` | 未被 websocket 接管的会话过期时间，默认 `60s` |

示例：

```
# 明文 HTTP + 认证
gowebssh.exe -p 2223 -auth admin:yourpassword

# HTTPS + 认证 + 审计
gowebssh.exe -p 2223 -auth admin:yourpassword -cert cert.pem -key key.pem
```

## 功能

- Web 终端（xterm.js），多标签会话可通过 `-tabs` 按需启用（默认单会话）
- SZ/RZ 文件上传下载（zmodem），另有 SFTP 文件管理面板（浏览/上传/下载/重命名/删除/新建目录）
- 断线自动重连（最多 3 次），SSH 客户端与 WebSocket 双向心跳保活
- 终端增强：WebGL 渲染、搜索（Ctrl+F）、链接识别、选中复制、右键粘贴
- 快捷命令栏：输入命令一键发送到当前终端
- 终端编码选择（UTF-8 / GBK / Big5），兼容老中文服务器
- SSH 代理跳板、主机/代理配置管理（hosts.html / proxies.html）
- 会话审计记录、HTTP Basic 认证、同源 WebSocket 校验、可选 TLS

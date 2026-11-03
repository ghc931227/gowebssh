package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/blacknon/go-sshlib"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	// sz fmt.Sprintf("%+q", "rz\r**\x18B00000000000000\r\x8a\x11")
	//ZModemSZStart = []byte{13, 42, 42, 24, 66, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 13, 138, 17}
	ZModemSZStart = []byte{42, 42, 24, 66, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 13, 138, 17}
	// sz 结束 fmt.Sprintf("%+q", "\r**\x18B0800000000022d\r\x8a")
	//ZModemSZEnd = []byte{13, 42, 42, 24, 66, 48, 56, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 50, 100, 13, 138}
	ZModemSZEnd = []byte{42, 42, 24, 66, 48, 56, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 50, 100, 13, 138}
	// sz 结束后可能还会发送两个 OO，但是经过测试发现不一定每次都会发送 fmt.Sprintf("%+q", "OO")
	ZModemSZEndOO = []byte{79, 79}

	// rz 的各种启动特征串
	ZModemRZStarts = [][]byte{
		// rz fmt.Sprintf("%+q", "**\x18B0100000023be50\r\x8a\x11")
		{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 48, 50, 51, 98, 101, 53, 48, 13, 138, 17},
		// rz -e fmt.Sprintf("%+q", "**\x18B0100000063f694\r\x8a\x11")
		{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 48, 54, 51, 102, 54, 57, 52, 13, 138, 17},
		// rz -S fmt.Sprintf("%+q", "**\x18B0100000223d832\r\x8a\x11")
		{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 50, 50, 51, 100, 56, 51, 50, 13, 138, 17},
		// rz -e -S fmt.Sprintf("%+q", "**\x18B010000026390f6\r\x8a\x11")
		{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 50, 54, 51, 57, 48, 102, 54, 13, 138, 17},
	}
	// rz 结束 fmt.Sprintf("%+q", "**\x18B0800000000022d\r\x8a")
	ZModemRZEnd = []byte{42, 42, 24, 66, 48, 56, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 50, 100, 13, 138}

	// **\x18B0
	ZModemRZCtrlStart = []byte{42, 42, 24, 66, 48}
	// \r\x8a\x11
	ZModemRZCtrlEnd1 = []byte{13, 138, 17}
	// \r\x8a
	ZModemRZCtrlEnd2 = []byte{13, 138}

	// zmodem 取消 \x18\x18\x18\x18\x18\x08\x08\x08\x08\x08
	ZModemCancel = []byte{24, 24, 24, 24, 24, 8, 8, 8, 8, 8}
)

func ByteContains(x, y []byte) (n []byte, contain bool) {
	index := bytes.Index(x, y)
	if index == -1 {
		return
	}
	lastIndex := index + len(y)
	n = append(x[:index], x[lastIndex:]...)
	return n, true
}

func UrlQueryUnescape(old string) (string, error) {
	// 客户端发送过来的数据是 url 编码过的，这里需要解码
	// url.QueryUnescape 会将'+'加号转换为' '空格。
	// 必须先替换 % ，再替换 +
	return url.QueryUnescape(strings.ReplaceAll(strings.ReplaceAll(old, "%", "%25"), "+", "%2b"))
}

// WebSSH 管理 Websocket 和 ssh 连接
type WebSSH struct {
	id                               string
	buffSize                         uint32
	term                             string
	cols                             int
	rows                             int
	sshConn                          net.Conn
	websocket                        *websocket.Conn
	connTimeout                      time.Duration
	logger                           *log.Logger
	DisableZModemSZ, DisableZModemRZ bool
	ZModemSZ, ZModemRZ, ZModemSZOO   bool

	// 连接保活与清理
	stopOnce sync.Once
	stopChan chan struct{}

	// 连接复用 (SFTP 等)
	connMu   sync.Mutex
	con      *sshlib.Connect
	sftpConn *sftp.Client

	// 会话结束回调 (用于从全局会话表中移除)
	OnClose func()

	// 审计输出 (为 nil 时关闭审计)
	audit io.WriteCloser

	// exec 模式: 连接后直接执行 command 而不是启动交互 shell
	execMode bool

	// connection info
	hostname      string
	port          string
	username      string
	password      string
	privatekey    string
	proxytype     string
	proxyhost     string
	proxyport     string
	proxyuser     string
	proxypassword string
	command       string
}

func (ws *WebSSH) Hostname() string {
	return ws.hostname
}

func (ws *WebSSH) SetHostname(hostname string) {
	ws.hostname = hostname
}

func (ws *WebSSH) Port() string {
	return ws.port
}

func (ws *WebSSH) SetPort(port string) {
	ws.port = port
}

func (ws *WebSSH) Username() string {
	return ws.username
}

func (ws *WebSSH) SetUsername(username string) {
	ws.username = username
}

func (ws *WebSSH) Password() string {
	return ws.password
}

func (ws *WebSSH) SetPassword(password string) {
	ws.password = password
}

func (ws *WebSSH) Privatekey() string {
	return ws.privatekey
}

func (ws *WebSSH) SetPrivatekey(privatekey string) {
	ws.privatekey = privatekey
}

func (ws *WebSSH) Proxytype() string {
	return ws.proxytype
}

func (ws *WebSSH) SetProxytype(proxytype string) {
	ws.proxytype = proxytype
}

func (ws *WebSSH) Proxyhost() string {
	return ws.proxyhost
}

func (ws *WebSSH) SetProxyhost(proxyhost string) {
	ws.proxyhost = proxyhost
}

func (ws *WebSSH) Proxyport() string {
	return ws.proxyport
}

func (ws *WebSSH) SetProxyport(proxyport string) {
	ws.proxyport = proxyport
}

func (ws *WebSSH) Proxyuser() string {
	return ws.proxyuser
}

func (ws *WebSSH) SetProxyuser(proxyuser string) {
	ws.proxyuser = proxyuser
}

func (ws *WebSSH) Proxypassword() string {
	return ws.proxypassword
}

func (ws *WebSSH) SetProxypassword(proxypassword string) {
	ws.proxypassword = proxypassword
}

func (ws *WebSSH) Command() string {
	return ws.command
}

func (ws *WebSSH) SetCommand(command string) {
	ws.command = command
}

// SetExecMode 设置 exec 模式：连接后执行 command 而非交互 shell
func (ws *WebSSH) SetExecMode(exec bool) {
	ws.execMode = exec
}

// SetAuditWriter 设置审计输出，会话期间输出的数据将写入该 writer
func (ws *WebSSH) SetAuditWriter(w io.WriteCloser) {
	ws.audit = w
}

// SetOnClose 注册会话结束回调
func (ws *WebSSH) SetOnClose(f func()) {
	ws.OnClose = f
}

// WebSSH 构造函数
func NewWebSSH() *WebSSH {
	return &WebSSH{
		buffSize:    DefaultBuffSize,
		logger:      DefaultLogger,
		term:        DefaultTerm,
		cols:        DefaultCols,
		rows:        DefaultRows,
		connTimeout: DefaultConnTimeout,
		stopChan:    make(chan struct{}),
	}
}

func (ws *WebSSH) DisableSZ() {
	ws.DisableZModemSZ = true
}

func (ws *WebSSH) EnableSZ() {
	ws.DisableZModemSZ = false
}

func (ws *WebSSH) DisableRZ() {
	ws.DisableZModemRZ = true
}

func (ws *WebSSH) EnableRZ() {
	ws.DisableZModemRZ = false
}

func (ws *WebSSH) SetLogger(logger *log.Logger) {
	ws.logger = logger
}

// 设置 buff 大小
func (ws *WebSSH) SetBuffSize(buffSize uint32) {
	ws.buffSize = buffSize
}

// 设置日志输出
func (ws *WebSSH) SetLogOut(out io.Writer) {
	ws.logger.SetOutput(out)
}

// 设置终端 term 类型
func (ws *WebSSH) SetTerm(term string) {
	ws.term = term
}

// 设置终端 term cols
func (ws *WebSSH) SetCols(cols int) {
	ws.cols = cols
}

// 设置终端 term rows
func (ws *WebSSH) SetRows(rows int) {
	ws.rows = rows
}

// 设置连接 id
func (ws *WebSSH) SetId(id string) {
	ws.id = id
}

// 设置连接超时时间
func (ws *WebSSH) SetConnTimeOut(connTimeout time.Duration) {
	ws.connTimeout = connTimeout
}

// dialSSH 建立到目标主机的 ssh 连接（含代理与认证），供交互会话与 SFTP 复用
func (ws *WebSSH) dialSSH() (*sshlib.Connect, error) {
	con := &sshlib.Connect{
		// If you use x11 forwarding, please set to true.
		ForwardX11: false,
		// If you use ssh-agent forwarding, please set to true.
		// And after, run `con.ConnectSshAgent()`.
		ForwardAgent: false,
	}
	// Create Proxy
	if ws.proxytype != "" && ws.proxyhost != "" {
		proxy := &sshlib.Proxy{
			Type:     ws.proxytype,
			Addr:     ws.proxyhost,
			Port:     ws.proxyport,
			Password: ws.proxypassword,
		}
		var err error
		con.ProxyDialer, err = proxy.CreateProxyDialer()
		if err != nil {
			return nil, err
		}
	}
	// Create ssh.AuthMethod
	var authMethod ssh.AuthMethod
	if ws.privatekey != "" {
		signer, err := sshlib.CreateSignerPublicKeyData([]byte(ws.privatekey), ws.password)
		if err != nil {
			return nil, err
		}
		authMethod = ssh.PublicKeys(signer)
	} else {
		authMethod = sshlib.CreateAuthMethodPassword(ws.password)
	}
	if err := con.CreateClient(ws.hostname, ws.port, ws.username, []ssh.AuthMethod{authMethod}); err != nil {
		return nil, err
	}
	return con, nil
}

// 添加 websocket 连接
func (ws *WebSSH) AddWebsocket(conn *websocket.Conn) {
	ws.logger.Printf("(%s) websocket connected", ws.id)
	ws.websocket = conn
	go func() {
		err := ws.server()
		ws.logger.Printf("(%s) websocket exit %v", ws.id, err)
		ws.cleanup()
	}()
}

// cleanup 会话结束后释放 ssh 连接、审计文件并触发回调
func (ws *WebSSH) cleanup() {
	ws.stopOnce.Do(func() {
		close(ws.stopChan)
	})
	ws.connMu.Lock()
	if ws.con != nil && ws.con.Client != nil {
		_ = ws.con.Client.Close()
		ws.con = nil
	}
	ws.sftpConn = nil
	ws.connMu.Unlock()
	if ws.audit != nil {
		_ = ws.audit.Close()
		ws.audit = nil
	}
	if ws.OnClose != nil {
		ws.OnClose()
	}
}

// auditWrite 将输出数据写入审计文件
func (ws *WebSSH) auditWrite(data []byte) {
	if ws.audit == nil {
		return
	}
	_, _ = ws.audit.Write(data)
}

// startKeepAlive 启动 ssh 客户端保活，连接断开时自动触发清理
func (ws *WebSSH) startKeepAlive(con *sshlib.Connect) {
	if con == nil || con.Client == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		failures := 0
		for {
			select {
			case <-ws.stopChan:
				return
			case <-ticker.C:
				if err := con.CheckClientAlive(); err != nil {
					failures++
					ws.logger.Printf("(%s) ssh keepalive failed (%d): %v", ws.id, failures, err)
					if failures >= 3 {
						ws.logger.Printf("(%s) ssh connection dead, closing", ws.id)
						if ws.websocket != nil {
							_ = ws.websocket.Close()
						}
						return
					}
					continue
				}
				failures = 0
			}
		}
	}()
}

// startWsPing 定期发送 websocket ping，防止中间设备掐断空闲连接
func (ws *WebSSH) startWsPing() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ws.stopChan:
				return
			case <-ticker.C:
				if ws.websocket == nil {
					return
				}
				_ = ws.websocket.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			}
		}
	}()
}

// 处理 websocket 连接发送过来的数据
func (ws *WebSSH) server() error {
	defer func() {
		_ = ws.websocket.Close()
	}()

	// websocket 读超时 + pong 保活
	_ = ws.websocket.SetReadDeadline(time.Now().Add(90 * time.Second))
	ws.websocket.SetPongHandler(func(string) error {
		return ws.websocket.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	ws.startWsPing()

	con, err := ws.dialSSH()
	if err != nil {
		return err
	}
	ws.connMu.Lock()
	ws.con = con
	ws.connMu.Unlock()
	ws.startKeepAlive(con)

	session, err := con.Client.NewSession()
	if err != nil {
		return err
	}
	defer func() {
		_ = session.Close()
	}()
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 8192,
		ssh.TTY_OP_OSPEED: 8192,
		ssh.IEXTEN:        0,
	}
	err = session.RequestPty(ws.term, ws.rows, ws.cols, modes)
	if err != nil {
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer func() {
		_ = stdin.Close()
	}()
	err = ws.transformOutput(session, ws.websocket)
	if err != nil {
		_ = ws.websocket.WriteJSON(&message{Type: messageTypeStderr, Data: []byte("get stdin & stderr channel error\r\n")})
		return errors.Wrap(err, "get stdin & stderr channel error")
	}

	if ws.execMode && ws.command != "" {
		// exec 模式：执行命令，结束后关闭会话
		err = session.Start(ws.command)
		if err != nil {
			_ = ws.websocket.WriteJSON(&message{Type: messageTypeStderr, Data: []byte("start command error\r\n")})
			return errors.Wrap(err, "start command error")
		}
		go func() {
			exitErr := session.Wait()
			if exitErr != nil {
				_ = ws.websocket.WriteJSON(&message{Type: messageTypeAlert, Data: []byte(fmt.Sprintf("command exited: %v", exitErr))})
			}
			// 明确告知客户端会话正常结束，前端据此跳过自动重连
			_ = ws.websocket.WriteJSON(&message{Type: messageTypeClosed, Data: []byte("command finished")})
			_ = ws.websocket.Close()
		}()
	} else {
		err = session.Shell()
		if err != nil {
			_ = ws.websocket.WriteJSON(&message{Type: messageTypeStderr, Data: []byte("start a login shell error\r\n")})
			return errors.Wrap(err, "start a login shell error")
		}
		// 监听 shell 正常退出（如用户手动 exit），通知前端避免误触发重连
		go func() {
			if exitErr := session.Wait(); exitErr != nil {
				_ = ws.websocket.WriteJSON(&message{Type: messageTypeAlert, Data: []byte(fmt.Sprintf("shell exited: %v", exitErr))})
			}
			_ = ws.websocket.WriteJSON(&message{Type: messageTypeClosed, Data: []byte("session closed")})
			_ = ws.websocket.Close()
		}()
	}

	for {
		var msg message

		msgType, data, err := ws.websocket.ReadMessage()
		if err != nil {
			return errors.Wrap(err, "websocket close or read message err")
		}
		// BinaryMessage 是 zmodem 数据流，则直接发送给 ssh 服务端, 可以提高 rz 上传速率
		if msgType == websocket.BinaryMessage {
			_, err = stdin.Write(data)
			if err != nil {
				return errors.Wrap(err, "write to stdin error")
			}
			continue
		} else {
			err = json.Unmarshal(data, &msg)
			if err != nil {
				return errors.Wrap(err, "error format input message")
			}
		}
		switch msg.Type {
		case messageTypeIgnore:
			// 忽略的信息，比如使用 rz 时，记录里面无法看到上传的文件，
			// 客户端上传完成可以可以发个忽略信息过来让服务端知晓
			data, _ := UrlQueryUnescape(string(msg.Data))
			ws.logger.Printf("(%s) Ignore message: %s", ws.id, data)
		case messageTypeStdin:
			data, _ := UrlQueryUnescape(string(msg.Data))
			_, err = stdin.Write([]byte(data))
			if err != nil {
				_ = ws.websocket.WriteJSON(&message{Type: messageTypeStderr, Data: []byte("write to stdin error\r\n")})
				return errors.Wrap(err, "write to stdin error")
			}

		case messageTypeResize:
			if msg.Cols <= 0 {
				msg.Cols = 80
			}
			if msg.Rows <= 0 {
				msg.Rows = 24
			}
			err = session.WindowChange(msg.Rows, msg.Cols)
			if err != nil {
				_ = ws.websocket.WriteJSON(&message{Type: messageTypeStderr, Data: []byte("resize error\r\n")})
				return errors.Wrap(err, "resize error")
			}
		default:
			ws.logger.Printf("unsupport input msg: %v", msg)
		}
	}
}

// 发送 ssh 会话的 stdout 和 stdin 数据到 websocket 连接
func (ws *WebSSH) transformOutput(session *ssh.Session, conn *websocket.Conn) error {
	stdout, err := session.StdoutPipe()
	if err != nil {
		return errors.Wrap(err, "get stdout channel error")
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return errors.Wrap(err, "get stderr channel error")
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "get stdin channel error")
	}

	copyToMessage := func(t messageType, r io.Reader, w io.WriteCloser) {
		buff := make([]byte, ws.buffSize)
		for {
			n, err := r.Read(buff)
			if err != nil {
				// stdout/stderr 结束说明会话即将退出，这里不关闭 websocket，
				// 由 session.Wait() 的 goroutine 发送 closed 消息后统一关闭，
				// 保证前端能收到正常结束信号而不误触发自动重连
				return
			}
			ws.auditWrite(buff[:n])

			if ws.ZModemSZOO {
				ws.ZModemSZOO = false
				// 经过测试 centos7-8 使用的 lrzsz-0.12.20 在 sz 结束时会发送 ZModemSZEndOO
				// 而 deepin20 等自带更新的 lrzsz-0.12.21rc 在 sz 结束时不会发送 ZModemSZEndOO， 而前端 zmodemjs
				// 库只有接收到 ZModemSZEndOO 才会认为 sz 结束，固这里需判断 sz 结束时是否发送了 ZModemSZEndOO，
				// 如果没有则手动发送一个，以便保证前端 zmodemjs 库正常运行（如果不发送，会导致使用 sz 命令时无法连续
				// 下载多个文件）。
				if n < 2 {
					// 手动发送 ZModemSZEndOO
					conn.WriteMessage(websocket.BinaryMessage, ZModemSZEndOO)
					conn.WriteJSON(&message{Type: t, Data: buff[:n]})
				} else if n == 2 {
					if buff[0] == ZModemSZEndOO[0] && buff[1] == ZModemSZEndOO[1] {
						conn.WriteMessage(websocket.BinaryMessage, ZModemSZEndOO)
					} else {
						// 手动发送 ZModemSZEndOO
						conn.WriteMessage(websocket.BinaryMessage, ZModemSZEndOO)
						conn.WriteJSON(&message{Type: t, Data: buff[:n]})
					}
				} else {
					if buff[0] == ZModemSZEndOO[0] && buff[1] == ZModemSZEndOO[1] {
						conn.WriteMessage(websocket.BinaryMessage, buff[:2])
						conn.WriteJSON(&message{Type: t, Data: buff[2:n]})
					} else {
						// 手动发送 ZModemSZEndOO
						conn.WriteMessage(websocket.BinaryMessage, ZModemSZEndOO)
						conn.WriteJSON(&message{Type: t, Data: buff[:n]})
					}
				}
			} else {
				if ws.ZModemSZ {
					if uint32(n) == ws.buffSize {
						// 如果读取的长度为 buffsize，则认为是在传输数据，
						// 这样可以提高 sz 下载速率，很低概率会误判 zmodem 取消操作
						conn.WriteMessage(websocket.BinaryMessage, buff[:n])
					} else {
						if x, ok := ByteContains(buff[:n], ZModemSZEnd); ok {
							ws.ZModemSZ = false
							ws.ZModemSZOO = true
							conn.WriteMessage(websocket.BinaryMessage, ZModemSZEnd)
							if len(x) != 0 {
								conn.WriteJSON(&message{Type: messageTypeConsole, Data: x})
							}
						} else if _, ok := ByteContains(buff[:n], ZModemCancel); ok {
							ws.ZModemSZ = false
							conn.WriteMessage(websocket.BinaryMessage, buff[:n])
						} else {
							conn.WriteMessage(websocket.BinaryMessage, buff[:n])
						}
					}
				} else if ws.ZModemRZ {
					if x, ok := ByteContains(buff[:n], ZModemRZEnd); ok {
						ws.ZModemRZ = false
						conn.WriteMessage(websocket.BinaryMessage, ZModemRZEnd)
						if len(x) != 0 {
							conn.WriteJSON(&message{Type: messageTypeConsole, Data: x})
						}
					} else if _, ok := ByteContains(buff[:n], ZModemCancel); ok {
						ws.ZModemRZ = false
						conn.WriteMessage(websocket.BinaryMessage, buff[:n])
					} else {
						// rz 上传过程中服务器端还是会给客户端发送一些信息，比如心跳
						//conn.WriteJSON(&message{Type: messageTypeConsole, Data: buff[:n]})
						//conn.WriteMessage(websocket.BinaryMessage, buff[:n])

						startIndex := bytes.Index(buff[:n], ZModemRZCtrlStart)
						if startIndex != -1 {
							endIndex := bytes.Index(buff[:n], ZModemRZCtrlEnd1)
							if endIndex != -1 {
								ctrl := append(ZModemRZCtrlStart, buff[startIndex+len(ZModemRZCtrlStart):endIndex]...)
								ctrl = append(ctrl, ZModemRZCtrlEnd1...)
								conn.WriteMessage(websocket.BinaryMessage, ctrl)
								info := append(buff[:startIndex], buff[endIndex+len(ZModemRZCtrlEnd1):n]...)
								if len(info) != 0 {
									conn.WriteJSON(&message{Type: messageTypeConsole, Data: info})
								}
							} else {
								endIndex = bytes.Index(buff[:n], ZModemRZCtrlEnd2)
								if endIndex != -1 {
									ctrl := append(ZModemRZCtrlStart, buff[startIndex+len(ZModemRZCtrlStart):endIndex]...)
									ctrl = append(ctrl, ZModemRZCtrlEnd2...)
									conn.WriteMessage(websocket.BinaryMessage, ctrl)
									info := append(buff[:startIndex], buff[endIndex+len(ZModemRZCtrlEnd2):n]...)
									if len(info) != 0 {
										conn.WriteJSON(&message{Type: messageTypeConsole, Data: info})
									}
								} else {
									conn.WriteJSON(&message{Type: messageTypeConsole, Data: buff[:n]})
								}
							}
						} else {
							conn.WriteJSON(&message{Type: messageTypeConsole, Data: buff[:n]})
						}
					}
				} else {
					if x, ok := ByteContains(buff[:n], ZModemSZStart); ok {
						if ws.DisableZModemSZ {
							conn.WriteJSON(&message{Type: messageTypeAlert, Data: []byte("sz download is disabled")})
							w.Write(ZModemCancel)
						} else {
							if y, ok := ByteContains(x, ZModemCancel); ok {
								// 下载不存在的文件以及文件夹(zmodem 不支持下载文件夹)时
								conn.WriteJSON(&message{Type: t, Data: y})
							} else {
								ws.ZModemSZ = true
								if len(x) != 0 {
									conn.WriteJSON(&message{Type: messageTypeConsole, Data: x})
								}
								conn.WriteMessage(websocket.BinaryMessage, ZModemSZStart)
							}
						}
					} else if x, ok := matchRZStart(buff[:n]); ok {
						if ws.DisableZModemRZ {
							conn.WriteJSON(&message{Type: messageTypeAlert, Data: []byte("rz upload is disabled")})
							w.Write(ZModemCancel)
						} else {
							ws.ZModemRZ = true
							if len(x) != 0 {
								conn.WriteJSON(&message{Type: messageTypeConsole, Data: x})
							}
							conn.WriteMessage(websocket.BinaryMessage, ZModemRZStarts[matchRZStartIndex(buff[:n])])
						}
					} else {
						conn.WriteJSON(&message{Type: t, Data: buff[:n]})
					}
				}
			}
		}
	}
	go copyToMessage(messageTypeStdout, stdout, stdin)
	go copyToMessage(messageTypeStderr, stderr, stdin)
	return nil
}

// matchRZStart 检查数据中是否包含任意一种 rz 启动特征串
// 返回值 x 为移除特征串后的剩余数据
func matchRZStart(data []byte) (x []byte, ok bool) {
	for _, start := range ZModemRZStarts {
		if _, found := ByteContains(append([]byte{}, data...), start); found {
			// 找到匹配后重新计算一次以获取剩余数据（ByteContains 会修改原切片）
			x, ok = ByteContains(data, start)
			return x, ok
		}
	}
	return nil, false
}

// matchRZStartIndex 返回数据中命中的 rz 启动特征串索引
func matchRZStartIndex(data []byte) int {
	for i, start := range ZModemRZStarts {
		if bytes.Contains(data, start) {
			return i
		}
	}
	return 0
}

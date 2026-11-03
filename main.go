package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	internal "github.com/ghc931227/gowebssh/internal"
	static "github.com/ghc931227/gowebssh/static"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// sessionEntry 会话条目
type sessionEntry struct {
	ssh     *internal.WebSSH
	created time.Time
}

// enableTabs 是否启用浏览器内多标签会话（默认关闭，-tabs 开启）
var enableTabs bool

// sessionStore 全局会话表（并发安全，含过期清理）
type sessionStore struct {
	mu    sync.Mutex
	items map[string]*sessionEntry
}

func newSessionStore() *sessionStore {
	return &sessionStore{items: make(map[string]*sessionEntry)}
}

func (s *sessionStore) put(id string, ws *internal.WebSSH) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[id] = &sessionEntry{ssh: ws, created: time.Now()}
}

// take 取出并从待连接表中移除（websocket 接管后由 OnClose 回调真正清理）
func (s *sessionStore) take(id string) *internal.WebSSH {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[id]
	if !ok {
		return nil
	}
	return entry.ssh
}

// remove 删除会话
func (s *sessionStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

// cleanupLoop 定期清理超过 ttl 未被 websocket 接管的会话，防止内存泄漏
func (s *sessionStore) cleanupLoop(ttl time.Duration) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			s.mu.Lock()
			now := time.Now()
			for id, entry := range s.items {
				if now.Sub(entry.created) > ttl {
					log.Printf("[webssh] session %s expired (not connected within %s)", id, ttl)
					delete(s.items, id)
				}
			}
			s.mu.Unlock()
		}
	}()
}

var (
	authUser     string
	authPassword string
	store        = newSessionStore()
)

// basicAuth 中间件：配置了 -auth 时对所有路由启用 HTTP Basic 认证
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return basicAuthHandler(next).(http.HandlerFunc)
}

func basicAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authUser == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userOk := subtle.ConstantTimeCompare([]byte(user), []byte(authUser)) == 1
		passOk := subtle.ConstantTimeCompare([]byte(pass), []byte(authPassword)) == 1
		if !ok || !userOk || !passOk {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebSSH"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOriginCheck websocket 跨源校验：仅允许同源请求
func sameOriginCheck(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// 非浏览器客户端（如 curl/wscat），交由 Basic 认证保护
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

func main() {
	var (
		serveport  string
		auth       string
		certFile   string
		keyFile    string
		auditDir   string
		sessionTTL time.Duration
	)
	flag.StringVar(&serveport, "p", "2223", "server port，default 2223")
	flag.StringVar(&auth, "auth", "", "HTTP Basic 认证，格式 user:password（不设置则不需要登录）")
	flag.BoolVar(&enableTabs, "tabs", false, "启用浏览器内多标签会话（默认关闭，同一页面仅一个会话）")
	flag.StringVar(&certFile, "cert", "", "TLS 证书文件，设置后启用 HTTPS")
	flag.StringVar(&keyFile, "key", "", "TLS 私钥文件")
	flag.StringVar(&auditDir, "audit", "sessions", "会话审计记录目录（设为空字符串关闭审计）")
	flag.DurationVar(&sessionTTL, "session-ttl", 60*time.Second, "未连接会话的过期时间，default 60s")
	flag.Parse()

	if auth != "" {
		parts := strings.SplitN(auth, ":", 2)
		if len(parts) != 2 {
			log.Fatal("-auth 格式错误，应为 user:password")
		}
		authUser, authPassword = parts[0], parts[1]
	}

	logger := log.New(os.Stderr, "[webssh] ", log.Ltime|log.Ldate)

	// 审计目录
	if auditDir != "" {
		if err := os.MkdirAll(auditDir, 0755); err != nil {
			log.Printf("[webssh] audit dir create failed, audit disabled: %v", err)
			auditDir = ""
		}
	}

	// 静态资源
	http.Handle("/", basicAuthHandler(http.FileServer(static.FS())))

	// 服务端功能开关，前端据此决定是否启用多标签等特性
	http.HandleFunc("/features.json", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tabs": %t}`, enableTabs)
	}))

	// 配置文件读取（需要认证，防止泄露保存的主机密码）
	http.HandleFunc("/config.json", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		file := GetCurrentDirectory() + "/config.json"
		if _, err := os.Stat(file); err != nil {
			_, _ = io.WriteString(w, "{}")
		} else {
			http.ServeFile(w, r, file)
		}
	}))

	// 配置保存（需要认证）
	http.HandleFunc("/save", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		config := r.FormValue("config")
		if len(config) > 4*1024*1024 {
			http.Error(w, "config too large", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(GetCurrentDirectory()+"/config.json", []byte(config), 0644); err != nil {
			log.Printf("[webssh] save config error: %v", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))

	// 创建会话
	http.HandleFunc("/ssh", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		webssh := internal.NewWebSSH()
		// term 可以使用 ansi, linux, vt100, xterm, dumb，除了 dumb外其他都有颜色显示, 默认 xterm-256color
		webssh.SetTerm(internal.TermXterm256Color)
		webssh.SetBuffSize(8192)
		webssh.SetId(id)
		webssh.SetConnTimeOut(5 * time.Second)
		webssh.SetLogger(logger)

		// 是否启用 sz 与 rz
		//webssh.DisableSZ()
		//webssh.DisableRZ()

		privatekeyfile, _, err := r.FormFile("privatekeyfile")
		// ErrMissingFile: multipart 但未选择文件; ErrNotMultipart: urlencoded 表单（console 方式调用）
		if err != nil && err != http.ErrMissingFile && err != http.ErrNotMultipart {
			http.Error(w, "read privatekey file error", http.StatusBadRequest)
			return
		}

		webssh.SetHostname(r.FormValue("hostname"))
		webssh.SetPort(r.FormValue("port"))
		webssh.SetUsername(r.FormValue("username"))
		webssh.SetPassword(r.FormValue("password"))
		webssh.SetPrivatekey(r.FormValue("privatekey"))
		if privatekeyfile != nil {
			var buf strings.Builder
			if _, err := io.Copy(&buf, privatekeyfile); err != nil {
				http.Error(w, "read privatekey file error", http.StatusBadRequest)
				return
			}
			webssh.SetPrivatekey(buf.String())
		}
		webssh.SetProxytype(r.FormValue("proxytype"))
		webssh.SetProxyhost(r.FormValue("proxyhost"))
		webssh.SetProxyport(r.FormValue("proxyport"))
		webssh.SetProxyuser(r.FormValue("proxyuser"))
		webssh.SetProxypassword(r.FormValue("proxypassword"))
		webssh.SetCommand(r.FormValue("command"))
		// exec 模式：mode=exec 时连接后直接执行 command
		if r.FormValue("mode") == "exec" && webssh.Command() != "" {
			webssh.SetExecMode(true)
		}

		// 审计：为该会话创建记录文件
		if auditDir != "" {
			auditName := fmt.Sprintf("%s-%s-%s@%s.log",
				time.Now().Format("20060102-150405"), id[:8], webssh.Username(), webssh.Hostname())
			f, err := os.Create(filepath.Join(auditDir, auditName))
			if err == nil {
				_, _ = fmt.Fprintf(f, "# session %s user=%s host=%s:%s started=%s\n",
					id, webssh.Username(), webssh.Hostname(), webssh.Port(), time.Now().Format(time.RFC3339))
				webssh.SetAuditWriter(f)
			} else {
				log.Printf("[webssh] create audit file error: %v", err)
			}
		}

		// 会话结束时从全局表中移除
		webssh.SetOnClose(func() {
			store.remove(id)
		})
		store.put(id, webssh)

		w.Header().Add("Content-Type", "application/json")
		encoding := r.FormValue("encoding")
		if encoding == "" {
			encoding = "UTF-8"
		}
		_, _ = fmt.Fprintf(w, `{"id": %q, "status": 0, "encoding": %q}`, id, encoding)
	}))

	// websocket 连接
	http.HandleFunc("/connect", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		webssh := store.take(id)
		if webssh == nil {
			http.Error(w, "session not found or expired", http.StatusNotFound)
			return
		}

		if !sameOriginCheck(r) {
			http.Error(w, "cross origin websocket not allowed", http.StatusForbidden)
			return
		}

		upGrader := websocket.Upgrader{
			// cross origin domain
			CheckOrigin: func(r *http.Request) bool {
				return sameOriginCheck(r)
			},
			// 处理 Sec-WebSocket-Protocol Header
			Subprotocols:    []string{"webssh"},
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
		}

		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[webssh] websocket upgrade error: %v", err)
			store.remove(id)
			return
		}

		//ws.SetCompressionLevel(4)
		//ws.EnableWriteCompression(true)

		webssh.AddWebsocket(ws)
	}))

	// ===== SFTP 文件管理接口 =====
	sftpGuard := func(h func(*internal.WebSSH, http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return basicAuth(func(w http.ResponseWriter, r *http.Request) {
			id := r.FormValue("id")
			if id == "" {
				id = r.URL.Query().Get("id")
			}
			webssh := store.take(id)
			if webssh == nil {
				http.Error(w, "session not found or expired", http.StatusNotFound)
				return
			}
			h(webssh, w, r)
		})
	}

	// 列目录
	http.HandleFunc("/sftp/list", sftpGuard(func(webssh *internal.WebSSH, w http.ResponseWriter, r *http.Request) {
		dir := r.FormValue("path")
		if dir == "" {
			dir = r.URL.Query().Get("path")
		}
		if dir == "" || dir == "~" {
			real, err := webssh.SftpRealPath(".")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			dir = real
		}
		items, err := webssh.SftpList(dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"path":  dir,
			"items": items,
		}); err != nil {
			log.Printf("[webssh] sftp list encode error: %v", err)
		}
	}))

	// 下载
	http.HandleFunc("/sftp/get", sftpGuard(func(webssh *internal.WebSSH, w http.ResponseWriter, r *http.Request) {
		p := r.FormValue("path")
		if p == "" {
			p = r.URL.Query().Get("path")
		}
		f, info, err := webssh.SftpOpen(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()
		w.Header().Add("Content-Type", "application/octet-stream")
		w.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(info.Name())))
		if info.Size() > 0 {
			w.Header().Add("Content-Length", fmt.Sprintf("%d", info.Size()))
		}
		_, _ = io.Copy(w, f)
	}))

	// 上传
	http.HandleFunc("/sftp/put", sftpGuard(func(webssh *internal.WebSSH, w http.ResponseWriter, r *http.Request) {
		// 允许最大 2GB 上传
		r.Body = http.MaxBytesReader(w, r.Body, 2048*1024*1024)
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "read upload file error: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }()
		p := r.FormValue("path")
		if p == "" {
			http.Error(w, "path is required", http.StatusBadRequest)
			return
		}
		remote, err := webssh.SftpCreate(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = remote.Close() }()
		if _, err := io.Copy(remote, file); err != nil {
			http.Error(w, "upload error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status": 0, "name": %q, "size": %d}`, header.Filename, header.Size)
	}))

	// 新建目录
	http.HandleFunc("/sftp/mkdir", sftpGuard(func(webssh *internal.WebSSH, w http.ResponseWriter, r *http.Request) {
		p := r.FormValue("path")
		if p == "" {
			http.Error(w, "path is required", http.StatusBadRequest)
			return
		}
		if err := webssh.SftpMkdir(p); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"status": 0}`)
	}))

	// 删除
	http.HandleFunc("/sftp/delete", sftpGuard(func(webssh *internal.WebSSH, w http.ResponseWriter, r *http.Request) {
		p := r.FormValue("path")
		if p == "" || p == "/" {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		if err := webssh.SftpDelete(p); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"status": 0}`)
	}))

	// 重命名/移动
	http.HandleFunc("/sftp/rename", sftpGuard(func(webssh *internal.WebSSH, w http.ResponseWriter, r *http.Request) {
		from := r.FormValue("from")
		to := r.FormValue("to")
		if from == "" || to == "" {
			http.Error(w, "from and to are required", http.StatusBadRequest)
			return
		}
		if err := webssh.SftpRename(from, to); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"status": 0}`)
	}))

	store.cleanupLoop(sessionTTL)

	srv := &http.Server{
		Addr:              ":" + serveport,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      0, // websocket 长连接不设写超时
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	// 优雅退出
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("[webssh] shutting down ...")
		_ = srv.Close()
	}()

	if certFile != "" && keyFile != "" {
		log.Println("start webssh server (https) @port " + serveport)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Println("start failed:", err)
		}
	} else {
		log.Println("start webssh server @port " + serveport)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("start failed:", err)
		}
	}
}

func GetCurrentDirectory() string {
	//返回绝对路径  filepath.Dir(os.Args[0])去除最后一个元素的路径
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	//将\替换成/
	return strings.Replace(dir, "\\", "/", -1)
}

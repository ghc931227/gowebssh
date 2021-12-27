package main

import (
	"bytes"
	"flag"
	internal "github.com/ghc931227/gowebssh/internal"
	static "github.com/ghc931227/gowebssh/static"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var sessionmap = make(map[string]*internal.WebSSH)

func main() {
	var serveport string
	flag.StringVar(&serveport, "p", "2223", "server port，default 2223")
	flag.Parse()

	//http.Handle("/", http.FileServer(http.Dir("./frontend")))
	http.Handle("/", http.FileServer(static.FS(false)))
	http.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		file := GetCurrentDirectory() + "/config.json"
		_, err := os.Stat(file)
		if err != nil {
			io.WriteString(w, "{}")
		} else {
			http.ServeFile(w, r, file)
		}
	})
	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		config := r.FormValue("config")
		err := ioutil.WriteFile(GetCurrentDirectory()+"/config.json", []byte(config), 0644)
		if err != nil {
			panic(err)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	http.HandleFunc("/ssh", func(w http.ResponseWriter, r *http.Request) {
		uuid, _ := uuid.NewUUID()
		webssh := internal.NewWebSSH()
		// term 可以使用 ansi, linux, vt100, xterm, dumb，除了 dumb外其他都有颜色显示, 默认 xterm-256color
		webssh.SetTerm(internal.TermXterm256Color)
		webssh.SetBuffSize(8192)
		webssh.SetId(uuid.String())
		webssh.SetConnTimeOut(5 * time.Second)
		webssh.SetLogger(log.New(os.Stderr, "[webssh] ", log.Ltime|log.Ldate))

		// 是否启用 sz 与 rz
		//webssh.DisableSZ()
		//webssh.DisableRZ()

		privatekeyfile, _, _ := r.FormFile("privatekeyfile")

		webssh.SetHostname(r.FormValue("hostname"))
		webssh.SetPort(r.FormValue("port"))
		webssh.SetUsername(r.FormValue("username"))
		webssh.SetPassword(r.FormValue("password"))
		webssh.SetPrivatekey(r.FormValue("privatekey"))
		if privatekeyfile != nil {
			var buf bytes.Buffer
			io.Copy(&buf, privatekeyfile)
			privatekey := buf.String()
			webssh.SetPrivatekey(privatekey)
		}
		webssh.SetProxytype(r.FormValue("proxytype"))
		webssh.SetProxyhost(r.FormValue("proxyhost"))
		webssh.SetProxyport(r.FormValue("proxyport"))
		webssh.SetProxyuser(r.FormValue("proxyuser"))
		webssh.SetProxypassword(r.FormValue("proxypassword"))
		webssh.SetCommand(r.FormValue("command"))

		sessionmap[uuid.String()] = webssh

		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, strings.Replace(`{"id": "$id", "status": 0, "encoding": "UTF-8"}`, "$id", uuid.String(), -1))
	})

	http.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		webssh := sessionmap[id]
		delete(sessionmap, id)

		upGrader := websocket.Upgrader{
			// cross origin domain
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
			// 处理 Sec-WebSocket-Protocol Header
			//Subprotocols: []string{r.Header.Get("Sec-WebSocket-Protocol")},
			Subprotocols:    []string{"webssh"},
			ReadBufferSize:  8192,
			WriteBufferSize: 8192,
		}

		ws, err := upGrader.Upgrade(w, r, nil)

		if err != nil {
			log.Panic(err)
		}

		//ws.SetCompressionLevel(4)
		//ws.EnableWriteCompression(true)

		webssh.AddWebsocket(ws)
	})

	log.Println("start webssh server @port " + serveport)
	err := http.ListenAndServe(":"+serveport, nil)
	if err != nil {
		log.Println("start faild:", err)
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

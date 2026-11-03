package internal

type messageType string

const (
	messageTypeAddr      = "addr"
	messageTypeTerm      = "term"
	messageTypeLogin     = "login"
	messageTypePassword  = "password"
	messageTypePublickey = "publickey"
	messageTypeStdin     = "stdin"
	messageTypeStdout    = "stdout"
	messageTypeStderr    = "stderr"
	messageTypeResize    = "resize"
	messageTypeIgnore    = "ignore"
	messageTypeConsole   = "console"
	messageTypeAlert     = "alert"
	// messageTypeClosed 服务端主动告知会话已正常结束（shell 退出或命令执行完成），
	// 客户端收到后不应触发自动重连
	messageTypeClosed = "closed"
)

type message struct {
	Type messageType `json:"type"`
	Data []byte      `json:"data,omitempty"`
	Cols int         `json:"cols,omitempty"`
	Rows int         `json:"rows,omitempty"`
}

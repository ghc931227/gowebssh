package static

import (
	"embed"
	"io/fs"
	"net/http"
)

// 内嵌静态资源（编译期打包，无需再依赖 esc 生成）
// 注意：只嵌入页面与静态资源目录，目录中混入的临时文件不会被包含。
//
//go:embed index.html hosts.html proxies.html css js img
var content embed.FS

// FS 返回内嵌静态资源的 http.FileSystem
func FS() http.FileSystem {
	sub, err := fs.Sub(content, ".")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

package internal

import (
	"os"
	"path"
	"sort"
	"time"

	"github.com/pkg/sftp"
)

// sftpClient 返回可用的 sftp 客户端。
// 优先复用当前会话的 ssh 连接；连接已失效时使用保存的凭据重新拨号。
func (ws *WebSSH) sftpClient() (*sftp.Client, error) {
	ws.connMu.Lock()
	defer ws.connMu.Unlock()

	// 复用已有连接，健康检查通过则直接返回
	if ws.sftpConn != nil && ws.con != nil {
		if _, err := ws.sftpConn.Stat("."); err == nil {
			return ws.sftpConn, nil
		}
		_ = ws.sftpConn.Close()
		ws.sftpConn = nil
	}

	// 复用 ssh 主连接
	if ws.con != nil && ws.con.Client != nil {
		if client, err := ws.con.OpenSFTP(); err == nil {
			ws.sftpConn = client
			return client, nil
		}
		// 主连接已失效，重建
		_ = ws.con.Client.Close()
		ws.con = nil
	}

	// 重新拨号
	con, err := ws.dialSSH()
	if err != nil {
		return nil, err
	}
	ws.con = con
	client, err := con.OpenSFTP()
	if err != nil {
		_ = con.Client.Close()
		ws.con = nil
		return nil, err
	}
	ws.sftpConn = client
	return client, nil
}

// SftpFileInfo 文件列表条目
type SftpFileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	IsDir   bool      `json:"isdir"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modtime"`
}

// SftpList 列出远端目录
func (ws *WebSSH) SftpList(dir string) ([]SftpFileInfo, error) {
	client, err := ws.sftpClient()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		dir = "."
	}
	infos, err := client.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	items := make([]SftpFileInfo, 0, len(infos))
	for _, info := range infos {
		items = append(items, SftpFileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			IsDir:   info.IsDir(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
		})
	}
	// 目录在前，名称排序
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return items[i].Name < items[j].Name
	})
	return items, nil
}

// SftpRealPath 解析相对路径（如 .、..）为绝对路径
func (ws *WebSSH) SftpRealPath(p string) (string, error) {
	client, err := ws.sftpClient()
	if err != nil {
		return "", err
	}
	if p == "" {
		return client.Getwd()
	}
	return client.RealPath(p)
}

// SftpOpen 打开远端文件用于下载
func (ws *WebSSH) SftpOpen(p string) (*sftp.File, os.FileInfo, error) {
	client, err := ws.sftpClient()
	if err != nil {
		return nil, nil, err
	}
	f, err := client.Open(p)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// SftpCreate 创建远端文件用于上传
func (ws *WebSSH) SftpCreate(p string) (*sftp.File, error) {
	client, err := ws.sftpClient()
	if err != nil {
		return nil, err
	}
	return client.Create(p)
}

// SftpMkdir 创建远端目录
func (ws *WebSSH) SftpMkdir(p string) error {
	client, err := ws.sftpClient()
	if err != nil {
		return err
	}
	return client.MkdirAll(p)
}

// SftpDelete 删除远端文件或目录（目录递归删除）
func (ws *WebSSH) SftpDelete(p string) error {
	client, err := ws.sftpClient()
	if err != nil {
		return err
	}
	info, err := client.Stat(p)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return ws.sftpRemoveDir(client, p)
	}
	return client.Remove(p)
}

func (ws *WebSSH) sftpRemoveDir(client *sftp.Client, dir string) error {
	items, err := client.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		child := path.Join(dir, item.Name())
		if item.IsDir() {
			if err := ws.sftpRemoveDir(client, child); err != nil {
				return err
			}
		} else if err := client.Remove(child); err != nil {
			return err
		}
	}
	return client.RemoveDirectory(dir)
}

// SftpRename 重命名/移动远端文件或目录
func (ws *WebSSH) SftpRename(oldPath, newPath string) error {
	client, err := ws.sftpClient()
	if err != nil {
		return err
	}
	return client.PosixRename(oldPath, newPath)
}

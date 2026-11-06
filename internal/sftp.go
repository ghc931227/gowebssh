package internal

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// maxSkippedReport 打包时最多记录的跳过条目数，仅用于日志，避免大目录下无限增长
const maxSkippedReport = 50

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

// ErrSftpInvalidPath 非法路径（空路径、根目录或包含 .. 段）
var ErrSftpInvalidPath = errors.New("非法路径")

// hasDotDot 判断路径中是否存在 .. 段，防止越界删除
func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// sftpDeleteError 把 SFTP 状态码转成可读文案，其余错误原样返回
func sftpDeleteError(err error, p string) error {
	var statusErr *sftp.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.FxCode() {
		case sftp.ErrSSHFxNoSuchFile:
			return fmt.Errorf("路径不存在: %s", p)
		case sftp.ErrSSHFxPermissionDenied:
			return fmt.Errorf("权限不足: %s", p)
		}
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("路径不存在: %s", p)
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("权限不足: %s", p)
	}
	return err
}

// SftpDelete 删除远端文件或目录（目录递归删除，符号链接只删链接本身）
func (ws *WebSSH) SftpDelete(p string) error {
	if p == "" || p == "/" || hasDotDot(p) {
		return ErrSftpInvalidPath
	}
	client, err := ws.sftpClient()
	if err != nil {
		return err
	}
	// 用 Lstat 判断类型：若 p 是符号链接则只删除链接，绝不递归进目标目录
	info, err := client.Lstat(p)
	if err != nil {
		return sftpDeleteError(err, p)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return client.Remove(p)
	}
	if info.IsDir() {
		return ws.sftpRemoveDir(client, p)
	}
	if err := client.Remove(p); err != nil {
		return sftpDeleteError(err, p)
	}
	return nil
}

func (ws *WebSSH) sftpRemoveDir(client *sftp.Client, dir string) error {
	items, err := client.ReadDir(dir)
	if err != nil {
		return sftpDeleteError(err, dir)
	}
	for _, item := range items {
		child := path.Join(dir, item.Name())
		// 以 Lstat 为准判断类型，避免把指向目录的符号链接当作目录递归
		childInfo, err := client.Lstat(child)
		if err != nil {
			// 并发删除时子项可能已不存在，跳过
			var statusErr *sftp.StatusError
			if errors.As(err, &statusErr) && statusErr.FxCode() == sftp.ErrSSHFxNoSuchFile {
				continue
			}
			return sftpDeleteError(err, child)
		}
		if childInfo.IsDir() {
			if err := ws.sftpRemoveDir(client, child); err != nil {
				return err
			}
			continue
		}
		if err := client.Remove(child); err != nil {
			return sftpDeleteError(err, child)
		}
	}
	if err := client.RemoveDirectory(dir); err != nil {
		return sftpDeleteError(err, dir)
	}
	return nil
}

// SftpRename 重命名/移动远端文件或目录
func (ws *WebSSH) SftpRename(oldPath, newPath string) error {
	client, err := ws.sftpClient()
	if err != nil {
		return err
	}
	return client.PosixRename(oldPath, newPath)
}

// SftpArchiveEntry 打包下载条目
type SftpArchiveEntry struct {
	Path    string      // 远端路径
	Rel     string      // zip 内的相对路径（已清洗）
	Size    int64       // 文件字节数（目录为 0）
	IsDir   bool        // 是否目录
	Mode    os.FileMode // 权限位
	ModTime time.Time   // 修改时间
}

// SftpScanResult 打包扫描结果（仅元数据，不读取文件内容）
type SftpScanResult struct {
	Files     int                // 常规文件数
	Dirs      int                // 目录数
	Bytes     int64              // 文件总字节数
	Entries   []SftpArchiveEntry // 打包条目（目录在前，字典序）
	Skipped   []string           // 无权限等原因跳过的路径（最多 maxSkippedReport 条）
	Truncated bool               // 条目数或总字节数超过上限，已提前停止遍历
}

// SftpScan 遍历 root 收集打包条目。只读取元数据，不读取文件内容。
// 条目数超过 maxEntries 或总字节数超过 maxBytes 时提前停止并标记 Truncated，
// 由调用方决定是拒绝请求还是继续。
func (ws *WebSSH) SftpScan(ctx context.Context, root string, maxEntries int, maxBytes int64) (*SftpScanResult, error) {
	client, err := ws.sftpClient()
	if err != nil {
		return nil, err
	}
	root = strings.TrimRight(root, "/")
	if root == "" {
		root = "/"
	}
	info, err := client.Stat(root)
	if err != nil {
		return nil, err
	}

	res := &SftpScanResult{}
	topName := path.Base(root)
	if topName == "" || topName == "." || topName == "/" {
		topName = "download"
	}

	// 单个文件：直接作为唯一条目
	if !info.IsDir() {
		res.Files = 1
		res.Bytes = info.Size()
		res.Entries = append(res.Entries, SftpArchiveEntry{
			Path:    root,
			Rel:     topName,
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		})
		if res.Bytes > maxBytes {
			res.Truncated = true
		}
		return res, nil
	}

	// 解析真实路径：Walk 基于 Lstat，若根目录本身是符号链接则无法下钻
	walkRoot := root
	if real, err := client.RealPath(root); err == nil {
		walkRoot = real
	}

	// 目录：把目录本身作为顶层条目写入，解压后保留根目录名，空目录也不会丢
	res.Dirs = 1
	res.Entries = append(res.Entries, SftpArchiveEntry{
		Path:    walkRoot,
		Rel:     topName,
		IsDir:   true,
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
	})

	// Walker 基于 Lstat，不跟随符号链接，天然避免软链接环
	walker := client.Walk(walkRoot)
	for walker.Step() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := walker.Path()
		if p == walkRoot {
			continue
		}
		if walker.Err() != nil {
			// 权限不足等：跳过该条目（目录不会继续下钻），不中断整包
			if len(res.Skipped) < maxSkippedReport {
				res.Skipped = append(res.Skipped, p)
			}
			continue
		}
		ei := walker.Stat()
		if ei == nil {
			continue
		}
		rel, ok := archiveEntryName(walkRoot, topName, p)
		if !ok {
			if len(res.Skipped) < maxSkippedReport {
				res.Skipped = append(res.Skipped, p)
			}
			continue
		}
		if ei.IsDir() {
			res.Dirs++
			res.Entries = append(res.Entries, SftpArchiveEntry{
				Path:    p,
				Rel:     rel,
				IsDir:   true,
				Mode:    ei.Mode(),
				ModTime: ei.ModTime(),
			})
			if len(res.Entries) > maxEntries {
				res.Truncated = true
				return res, nil
			}
			continue
		}
		if !ei.Mode().IsRegular() {
			// 符号链接、设备文件等无法可靠打包，跳过
			if len(res.Skipped) < maxSkippedReport {
				res.Skipped = append(res.Skipped, p)
			}
			continue
		}
		res.Files++
		res.Bytes += ei.Size()
		res.Entries = append(res.Entries, SftpArchiveEntry{
			Path:    p,
			Rel:     rel,
			Size:    ei.Size(),
			Mode:    ei.Mode(),
			ModTime: ei.ModTime(),
		})
		if len(res.Entries) > maxEntries || res.Bytes > maxBytes {
			res.Truncated = true
			return res, nil
		}
	}
	return res, nil
}

// archiveEntryName 计算 zip 内条目名：top/ 下的相对路径，拒绝越界与空段
func archiveEntryName(root, top, p string) (string, bool) {
	rel := strings.TrimPrefix(p, root)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", false
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == ".." {
			return "", false
		}
	}
	return top + "/" + rel, true
}

// SftpZip 将扫描结果流式写入 w（zip 格式，默认 Store 不压缩），不落盘。
// 单个文件打开/读取失败时记录日志并跳过，不中断整包；
// 客户端取消（ctx 结束）或响应写入失败时返回错误，由调用方记录。
func (ws *WebSSH) SftpZip(ctx context.Context, entries []SftpArchiveEntry, w io.Writer) error {
	client, err := ws.sftpClient()
	if err != nil {
		return err
	}
	zw := zip.NewWriter(w)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			_ = zw.Close()
			return err
		}
		h := &zip.FileHeader{Name: entry.Rel, Method: zip.Store, Modified: entry.ModTime}
		h.SetMode(entry.Mode)
		if entry.IsDir {
			// 目录条目按 zip 约定以 / 结尾，避免被解压工具当成空文件
			h.Name = strings.TrimSuffix(entry.Rel, "/") + "/"
			if _, err := zw.CreateHeader(h); err != nil {
				_ = zw.Close()
				return err
			}
			continue
		}
		// 先打开远端文件，打不开就整条跳过，避免在 zip 里留下同名空文件
		f, err := client.Open(entry.Path)
		if err != nil {
			ws.logger.Printf("[sftp] zip skip %s: %v", entry.Path, err)
			continue
		}
		dst, err := zw.CreateHeader(h)
		if err != nil {
			_ = f.Close()
			_ = zw.Close()
			return err
		}
		if _, err := io.Copy(dst, f); err != nil {
			_ = f.Close()
			// 客户端断开时 ctx 会被取消，此时应停止整个打包
			if ctxErr := ctx.Err(); ctxErr != nil {
				_ = zw.Close()
				return ctxErr
			}
			ws.logger.Printf("[sftp] zip read %s failed: %v", entry.Path, err)
			continue
		}
		_ = f.Close()
	}
	return zw.Close()
}

/**
 * i18n：中英文国际化
 * - 默认按浏览器语言检测（zh* 用中文，否则英文），localStorage 记住手动选择
 * - 静态文本用 data-i18n / data-i18n-placeholder / data-i18n-title 属性标注
 * - JS 动态文案用 t('key')
 * - 页面中放入 <span class="lang-switch"></span> 即可自动渲染切换按钮
 */
(function () {
    'use strict';

    var DICT = {
        zh: {
            // 连接表单
            'head.title': 'SSH 连接',
            'label.savedHosts': '已保存主机',
            'label.proxy': '连接代理（可选）',
            'label.hostname': '主机地址',
            'ph.hostname': '例：192.168.1.10',
            'label.port': '端口',
            'label.username': '用户名',
            'label.password': '密码',
            'label.privatekey': '私钥 PrivateKey（可选，口令填在下方密码框）',
            'label.encoding': '编码',
            'label.command': '登录后命令（可选）',
            'ph.command': '登录后自动执行',
            'proxy.title': '代理设置',
            'label.proxytype': '类型',
            'ph.proxytype': 'socks5 / http',
            'label.proxyhost': '地址',
            'btn.connect': '连 接',
            'btn.hosts': '主机管理',
            'btn.proxies': '代理管理',
            // 标签栏
            'tab.new': '新建连接',
            'tab.sftp': '文件管理',
            'tab.close': '关闭',
            'tab.disconnect': '断开',
            // SFTP 面板
            'sftp.go': '前往',
            'sftp.up': '上级',
            'sftp.refresh': '刷新',
            'sftp.mkdir': '新建目录',
            'sftp.newfile': '新建文件',
            'sftp.upload': '上传文件',
            'th.name': '名称',
            'th.size': '大小',
            'th.perm': '权限',
            'th.mtime': '修改时间',
            'th.actions': '操作',
            'btn.download': '下载',
            'btn.rename': '改名',
            'btn.delete': '删除',
            // 动态提示
            'msg.noSession': '请先连接会话',
            'msg.noActiveSession': '没有活动会话',
            'msg.authFailed': '认证失败，请刷新页面重新登录',
            'msg.sftpFail': 'SFTP 操作失败: ',
            'msg.confirmDelete': '确认删除 ',
            'prompt.newName': '新名称:',
            'prompt.dirname': '目录名:',
            'prompt.filename': '文件名:',
            'msg.downloadFail': '下载失败: ',
            'msg.fileCreated': '文件已创建: ',
            'msg.allUploaded': '全部上传完成',
            'msg.uploading': '上传 ',
            'msg.uploadFail': ' 上传失败: ',
            'msg.uploadFailShort': ' 上传失败',
            'msg.reconnect': '正在重连 {t} (第 {n} 次) ...',
            'msg.disconnectFail': ' 连接已断开，自动重连失败。',
            'msg.tooLargeUp': ' 超过 2048 MB, 无法上传',
            'msg.tooLargeDl': ' 超过 2048 MB, 无法下载',
            'msg.tooMany': '上传文件个数不能超过 25 个',
            // 弹窗
            'upload.title': '上传文件',
            'upload.pick': '点击选择文件',
            'btn.close': '关闭',
            'btn.cancel': '取消',
            'btn.okUpload': '确定并上传',
            'editor.title': '新建文件: ',
            'ph.editor': '输入文件内容（可以为空）',
            'search.ph': '搜索 (回车下一个)',
            // 主机/代理管理页
            'btn.up': '上移',
            'btn.down': '下移',
            'btn.save': '保存',
            'btn.back': '返回',
            'hosts.add': '添加主机',
            'proxies.add': '添加代理'
        },
        en: {
            'head.title': 'SSH Connection',
            'label.savedHosts': 'Saved Hosts',
            'label.proxy': 'Proxy (optional)',
            'label.hostname': 'Hostname',
            'ph.hostname': 'e.g. 192.168.1.10',
            'label.port': 'Port',
            'label.username': 'Username',
            'label.password': 'Password',
            'label.privatekey': 'Private Key (optional; passphrase goes in the Password field)',
            'label.encoding': 'Encoding',
            'label.command': 'Command after login (optional)',
            'ph.command': 'auto-run after login',
            'proxy.title': 'Proxy Settings',
            'label.proxytype': 'Type',
            'ph.proxytype': 'socks5 / http',
            'label.proxyhost': 'Host',
            'btn.connect': 'Connect',
            'btn.hosts': 'Hosts',
            'btn.proxies': 'Proxies',
            'tab.new': 'New connection',
            'tab.sftp': 'Files',
            'tab.close': 'Close',
            'tab.disconnect': 'Disconnect',
            'sftp.go': 'Go',
            'sftp.up': 'Up',
            'sftp.refresh': 'Refresh',
            'sftp.mkdir': 'New Folder',
            'sftp.newfile': 'New File',
            'sftp.upload': 'Upload',
            'th.name': 'Name',
            'th.size': 'Size',
            'th.perm': 'Perms',
            'th.mtime': 'Modified',
            'th.actions': 'Actions',
            'btn.download': 'Download',
            'btn.rename': 'Rename',
            'btn.delete': 'Delete',
            'msg.noSession': 'Connect to a session first',
            'msg.noActiveSession': 'No active session',
            'msg.authFailed': 'Authentication failed, please refresh and login again',
            'msg.sftpFail': 'SFTP operation failed: ',
            'msg.confirmDelete': 'Delete ',
            'prompt.newName': 'New name:',
            'prompt.dirname': 'Directory name:',
            'prompt.filename': 'File name:',
            'msg.downloadFail': 'Download failed: ',
            'msg.fileCreated': 'File created: ',
            'msg.allUploaded': 'All uploads finished',
            'msg.uploading': 'Uploading ',
            'msg.uploadFail': ' upload failed: ',
            'msg.uploadFailShort': ' upload failed',
            'msg.reconnect': 'Reconnecting {t} (attempt {n}) ...',
            'msg.disconnectFail': ' disconnected, auto-reconnect failed.',
            'msg.tooLargeUp': ' exceeds 2048 MB, cannot upload',
            'msg.tooLargeDl': ' exceeds 2048 MB, cannot download',
            'msg.tooMany': 'Cannot upload more than 25 files at once',
            'upload.title': 'Upload Files',
            'upload.pick': 'Click to choose files',
            'btn.close': 'Close',
            'btn.cancel': 'Cancel',
            'btn.okUpload': 'Create & Upload',
            'editor.title': 'New file: ',
            'ph.editor': 'File content (can be empty)',
            'search.ph': 'Search (Enter for next)',
            'btn.up': 'Up',
            'btn.down': 'Down',
            'btn.save': 'Save',
            'btn.back': 'Back',
            'hosts.add': 'Add a Host',
            'proxies.add': 'Add a Proxy'
        }
    };

    var LANG_KEY = 'gowebssh-lang';

    function detectLang() {
        var saved = null;
        try { saved = window.localStorage.getItem(LANG_KEY); } catch (e) {}
        if (saved === 'zh' || saved === 'en') return saved;
        var nav = (navigator.language || navigator.userLanguage || 'en').toLowerCase();
        return nav.indexOf('zh') === 0 ? 'zh' : 'en';
    }

    var g_lang = detectLang();

    function t(key) {
        var d = DICT[g_lang] || DICT.en;
        return (key in d) ? d[key] : (DICT.en[key] || key);
    }

    function applyI18n(root) {
        var $scope = root ? $(root) : $(document);
        $scope.find('[data-i18n]').addBack('[data-i18n]').each(function () {
            $(this).text(t($(this).attr('data-i18n')));
        });
        $scope.find('[data-i18n-placeholder]').addBack('[data-i18n-placeholder]').each(function () {
            $(this).attr('placeholder', t($(this).attr('data-i18n-placeholder')));
        });
        $scope.find('[data-i18n-title]').addBack('[data-i18n-title]').each(function () {
            $(this).attr('title', t($(this).attr('data-i18n-title')));
        });
    }

    function renderSwitchButtons() {
        $('.lang-switch').each(function () {
            var next = g_lang === 'zh' ? 'EN' : '中文';
            $(this).empty().append(
                $('<button type="button" class="btn btn-link btn-sm lang-btn" style="padding:0;color:inherit;text-decoration:underline;"></button>')
                    .text(next)
            );
        });
    }

    function setLang(lang) {
        g_lang = lang;
        try { window.localStorage.setItem(LANG_KEY, lang); } catch (e) {}
        renderSwitchButtons();
        applyI18n();
        $(document).trigger('langchange', [lang]);
    }

    // 全局暴露
    window.t = t;
    window.g_lang = g_lang;
    window.applyI18n = applyI18n;
    window.setLang = setLang;

    $(function () {
        $(document).on('click', '.lang-btn', function () {
            setLang(g_lang === 'zh' ? 'en' : 'zh');
        });
        renderSwitchButtons();
        applyI18n();
    });
})();

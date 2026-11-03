/*jslint browser:true */

var jQuery;
var wssh = {};


(function() {
    // For FormData without getter and setter
    var proto = FormData.prototype,
        data = {};

    if (!proto.get) {
        proto.get = function (name) {
            if (data[name] === undefined) {
                var input = document.querySelector('input[name="' + name + '"]'),
                    value;
                if (input) {
                    if (input.type === 'file') {
                        value = input.files[0];
                    } else {
                        value = input.value;
                    }
                    data[name] = value;
                }
            }
            return data[name];
        };
    }

    if (!proto.set) {
        proto.set = function (name, value) {
            data[name] = value;
        };
    }
}());


jQuery(function($){
    var status = $('#status'),
        button = $('.btn-primary'),
        form_view = $('#form-view'),
        form_status_wrap = $('#form-status-wrap'),
        term_view = $('#term-view'),
        tabbar = $('#tabbar'),
        session_stack = $('#session-stack'),
        waiter = $('#waiter'),
        term_type = $('#term'),
        style = {},
        default_title = 'WebSSH',
        title_element = document.querySelector('title'),
        form_id = '#connect',
        debug = document.querySelector(form_id).noValidate,
        custom_font = get_custom_font(),
        default_fonts,
        DISCONNECTED = 0,
        CONNECTING = 1,
        CONNECTED = 2,
        state = DISCONNECTED,
        messages = {1: 'This client is connecting ...', 2: 'This client is already connnected.'},
        key_max_size = 16384,
        fields = ['hostname', 'port', 'username'],
        form_keys = fields.concat(['password', 'totp', 'encoding']),
        opts_keys = ['bgcolor', 'title', 'encoding', 'command', 'term'],
        url_form_data = {},
        url_opts_data = {},
        validated_form_data,
        event_origin,
        MAX_RECONNECT = 3,
        hostname_tester = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;

    // 只信任白名单中的自定义字体，忽略浏览器扩展注入的任意字体（如 PixelColeco）。
    // 如需启用自定义终端字体，把 font-family 名称加入 allowlist，例如 ['MyFont']。
    function get_custom_font() {
        var allowlist = [];
        if (!document.fonts || !allowlist.length) {
            return undefined;
        }
        var fonts = document.fonts.values(),
            f = fonts.next();
        while (!f.done) {
            if (allowlist.indexOf(f.value.family) !== -1) {
                return f.value;
            }
            f = fonts.next();
        }
        return undefined;
    }

    function utf8_to_b64(rawString) {
        return btoa(unescape(encodeURIComponent(rawString)));
    }

    function b64_to_utf8(encodeString) {
        return decodeURIComponent(escape(atob(encodeString)));
    }

    function store_items(names, data) {
        var i, name, value;

        for (i = 0; i < names.length; i++) {
            name = names[i];
            value = data.get(name);
            if (value){
                window.localStorage.setItem(name, value);
            }
        }
    }


    function restore_items(names) {
        var i, name, value;

        for (i=0; i < names.length; i++) {
            name = names[i];
            value = window.localStorage.getItem(name);
            if (value) {
                $('#'+name).val(value);
            }
        }
    }


    function populate_form(data) {
        var names = form_keys.concat(['passphrase']),
            i, name;

        for (i=0; i < names.length; i++) {
            name = names[i];
            $('#'+name).val(data.get(name));
        }
    }


    function get_object_length(object) {
        return Object.keys(object).length;
    }


    function decode_uri(uri) {
        try {
            return decodeURI(uri);
        } catch(e) {
            console.error(e);
        }
        return '';
    }


    function decode_password(encoded) {
        try {
            return window.atob(encoded);
        } catch (e) {
            console.error(e);
        }
        return null;
    }


    function parse_url_data(string, form_keys, opts_keys, form_map, opts_map) {
        var i, pair, key, val,
            arr = string.split('&');

        for (i = 0; i < arr.length; i++) {
            pair = arr[i].split('=');
            key = pair[0].trim().toLowerCase();
            val = pair.slice(1).join('=').trim();

            if (form_keys.indexOf(key) >= 0) {
                form_map[key] = val;
            } else if (opts_keys.indexOf(key) >=0) {
                opts_map[key] = val;
            }
        }

        if (form_map.password) {
            form_map.password = decode_password(form_map.password);
        }
    }


    function parse_xterm_style() {
        var text = $('.xterm-helpers style').text();
        var arr = text.split('xterm-normal-char{width:');
        style.width = parseFloat(arr[1]);
        arr = text.split('div{height:');
        style.height = parseFloat(arr[1]);
    }


    function get_cell_size(term) {
        style.width = term._core._renderService._renderer.dimensions.actualCellWidth;
        style.height = term._core._renderService._renderer.dimensions.actualCellHeight;
    }


    function current_geometry(term) {
        if (!style.width || !style.height || isNaN(style.width) || isNaN(style.height)) {
            try {
                get_cell_size(term);
            } catch (TypeError) {
                parse_xterm_style();
            }
        }

        var cols = parseInt(window.innerWidth / style.width, 10) - 1;
        var rows = parseInt(window.innerHeight / style.height, 10);

        // 新版 xterm 内部结构变化导致尺寸解析失败时回退到安全值，避免 resize(NaN) 抛异常
        if (isNaN(cols) || cols < 10) {
            cols = 80;
        }
        if (isNaN(rows) || rows < 5) {
            rows = 24;
        }
        return {'cols': cols, 'rows': rows};
    }


    function format_geometry(cols, rows) {
        return JSON.stringify({'cols': cols, 'rows': rows});
    }


    function read_as_text_with_decoder(file, callback, decoder) {
        var reader = new window.FileReader();

        if (decoder === undefined) {
            decoder = new window.TextDecoder('utf-8', {'fatal': true});
        }

        reader.onload = function() {
            var text;
            try {
                text = decoder.decode(reader.result);
            } catch (TypeError) {
                console.log('Decoding error happened.');
            } finally {
                if (callback) {
                    callback(text);
                }
            }
        };

        reader.onerror = function (e) {
            console.error(e);
        };

        reader.readAsArrayBuffer(file);
    }


    function read_as_text_with_encoding(file, callback, encoding) {
        var reader = new window.FileReader();

        if (encoding === undefined) {
            encoding = 'utf-8';
        }

        reader.onload = function() {
            if (callback) {
                callback(reader.result);
            }
        };

        reader.onerror = function (e) {
            console.error(e);
        };

        reader.readAsText(file, encoding);
    }


    function read_file_as_text(file, callback, decoder) {
        if (!window.TextDecoder) {
            read_as_text_with_encoding(file, callback, decoder);
        } else {
            read_as_text_with_decoder(file, callback, decoder);
        }
    }


    function log_status(text, to_populate) {
        // 表单视图显示错误信息
        form_view.removeClass('hide');
        form_status_wrap.removeClass('hide');
        term_view.addClass('hide');
        console.log(text);
        status.html(text.split('\n').join('<br/>'));

        if (to_populate && validated_form_data) {
            populate_form(validated_form_data);
            validated_form_data = undefined;
        }

        if (waiter.css('display') !== 'none') {
            waiter.hide();
        }
    }


    function bytesHuman(bytes, precision) {
        if (!/^([-+])?|(\.\d+)(\d+(\.\d+)?|(\d+\.)|Infinity)$/.test(bytes)) {
            return '-'
        }
        if (bytes === 0) return '0';
        if (typeof precision === 'undefined') precision = 1;
        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB', 'BB'];
        const num = Math.floor(Math.log(bytes) / Math.log(1024));
        const value = (bytes / Math.pow(1024, Math.floor(num))).toFixed(precision);
        return `${value} ${units[num]}`
    }

    // addon 全局变量兼容处理（UMD 包可能是命名空间或直接构造函数）
    function addon_ctor(global_name) {
        var mod = window[global_name];
        if (!mod) {
            return null;
        }
        return mod[global_name] || mod.default || (typeof mod === 'function' ? mod : null);
    }


    // ==========================================================================
    // 会话 (Session)：一个标签页 = 一个 websocket + 一个 xterm 实例
    // ==========================================================================
    var sessions = [];
    var active_session = null;
    // 服务端功能开关，默认关闭多标签（与 -tabs 参数对应）
    var FEATURES = { tabs: false };

    $.ajax({
        url: '/features.json',
        type: 'get',
        dataType: 'json',
        cache: false
    }).done(function (res) {
        if (res && typeof res.tabs === 'boolean') {
            FEATURES.tabs = res.tabs;
        }
        if (!FEATURES.tabs) {
            // 单会话模式：隐藏"新建连接"按钮，仅保留当前会话标题与断开按钮
            $('#tab-new').addClass('hide');
        }
    });

    function Session(form_data, title) {
        var self = this;
        this.id = null;
        this.form_data = form_data;
        this.title = title || 'WebSSH';
        this.encoding = 'utf-8';
        this.decoder = window.TextDecoder ? new window.TextDecoder('utf-8') : 'utf-8';
        this.state = DISCONNECTED;
        this.sock = undefined;
        this.term = undefined;
        this.zsentry = undefined;
        this.reconnect_attempts = 0;
        this.user_closed = false;
        this.closed_normally = false;
        this.resized = false;

        // DOM
        this.pane = $('<div class="session-pane"><div class="terminal-container"></div></div>');
        this.container = this.pane.find('.terminal-container')[0];
        session_stack.append(this.pane);

        this.tab = $('<li class="session-tab"><span class="tab-title"></span><span class="tab-close" data-i18n-title="tab.close">×</span></li>');
        applyI18n(this.tab);
        this.tab.find('.tab-title').text(this.title);
        this.tab.find('.tab-close').on('click', function (e) {
            e.stopPropagation();
            self.dispose();
        });
        this.tab.on('click', function () {
            self.activate();
        });
        $('#tab-new').before(this.tab);
        tabbar.show();
    }

    Session.prototype.activate = function () {
        var self = this;
        if (active_session === this) {
            this.focus();
            return;
        }
        active_session = this;
        $.each(sessions, function (i, s) {
            s.pane.removeClass('active');
            s.tab.removeClass('active');
        });
        this.pane.addClass('active');
        this.tab.addClass('active');
        setTimeout(function () {
            self.fit();
            self.focus();
        }, 50);
    };

    Session.prototype.focus = function () {
        if (this.term && this.state === CONNECTED) {
            this.term.focus();
        }
    };

    Session.prototype.fit = function () {
        if (!this.term || !this.term.fitAddon) {
            return;
        }
        try {
            this.term.fitAddon.fit();
        } catch (e) {
            console.log('fit error', e);
        }
    };

    Session.prototype.term_write = function (text) {
        if (this.term) {
            this.term.write(text);
            if (!this.resized) {
                this.resize_to_window();
                this.resized = true;
            }
        }
    };

    Session.prototype.resize_to_window = function () {
        if (!this.term || !this.term.fitAddon) {
            return;
        }
        // 以 fit() 计算出的真实行列数为准，避免手工解析 xterm 内部尺寸出错
        this.fit();
        if (this.term.cols && this.term.rows) {
            this.on_resize(this.term.cols, this.term.rows);
        }
    };

    Session.prototype.on_resize = function (cols, rows) {
        if (cols !== this.cols || rows !== this.rows) {
            this.cols = cols;
            this.rows = rows;
            if (this.term) {
                this.term.resize(cols, rows);
            }
            this.send_resize_msg(cols, rows);
        }
    };

    Session.prototype.send_resize_msg = function (cols, rows) {
        if (this.sock && this.sock.readyState === window.WebSocket.OPEN) {
            this.sock.send(JSON.stringify({ type: 'resize', cols: cols, rows: rows }));
        }
    };

    Session.prototype.send_stdin = function (data) {
        if (!this.sock || this.sock.readyState !== window.WebSocket.OPEN) {
            console.log('Websocket was already closed');
            return;
        }
        this.sock.send(JSON.stringify({ type: 'stdin', data: utf8_to_b64(data) }));
    };

    Session.prototype.set_encoding = function (new_encoding) {
        var self = this;
        if (!new_encoding) {
            console.log('An encoding is required');
            return false;
        }
        if (!window.TextDecoder) {
            self.decoder = new_encoding;
            self.encoding = new_encoding;
            return true;
        }
        try {
            self.decoder = new window.TextDecoder(new_encoding);
            self.encoding = self.decoder.encoding;
            console.log('Set encoding to ' + self.encoding);
            return true;
        } catch (RangeError) {
            console.log('Unknown encoding ' + new_encoding);
            return false;
        }
    };

    // 加载 xterm 增强插件
    Session.prototype.setup_term = function () {
        var self = this;
        var term = new window.Terminal({
            fontSize: 18,
            cursorBlink: true,
            cursorStyle: 'bar',
            scrollback: 5000,
            theme: {
                background: url_opts_data.bgcolor || 'black'
            }
        });
        this.term = term;
        term.fitAddon = new window.FitAddon.FitAddon();
        term.loadAddon(term.fitAddon);

        var WebLinks = addon_ctor('WebLinksAddon');
        if (WebLinks) {
            try { term.loadAddon(new WebLinks()); } catch (e) { console.log(e); }
        }

        var Search = addon_ctor('SearchAddon');
        if (Search) {
            try {
                self.searchAddon = new Search();
                term.loadAddon(self.searchAddon);
            } catch (e) { console.log(e); }
        }

        var Webgl = addon_ctor('WebglAddon');
        if (Webgl) {
            try {
                self.webglAddon = new Webgl();
                self.webglAddon.onContextLoss = function () {
                    console.log('webgl context loss, fallback to dom renderer');
                    if (self.webglAddon) {
                        self.webglAddon.dispose();
                        self.webglAddon = undefined;
                    }
                };
                term.loadAddon(self.webglAddon);
            } catch (e) { console.log(e); }
        }

        term.onData(function (data) {
            self.send_stdin(data);
        });

        term.onResize(function (geom) {
            self.send_resize_msg(geom.cols, geom.rows);
        });

        // 选中即复制
        if (term.onSelectionChange) {
            term.onSelectionChange(function () {
                var text = term.getSelection();
                if (text && navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).catch(function () {});
                }
            });
        }

        // 右键粘贴
        $(self.container).on('contextmenu', function (e) {
            e.preventDefault();
            if (navigator.clipboard && navigator.clipboard.readText) {
                navigator.clipboard.readText().then(function (text) {
                    if (text) {
                        self.send_stdin(text);
                    }
                }).catch(function () {});
            }
        });

        // Ctrl+F 搜索
        term.attachCustomKeyEventHandler(function (e) {
            if (e.type === 'keydown' && (e.ctrlKey || e.metaKey) && e.key === 'f') {
                self.open_search();
                return false;
            }
            return true;
        });

        term.open(this.container);
        this.setup_search_box();
    };

    Session.prototype.setup_search_box = function () {
        var self = this;
        var box = $(
            '<div class="term-search" style="display:none;">' +
            '<input type="text" data-i18n-placeholder="search.ph" placeholder="' + t('search.ph') + '"/>' +
            '<button type="button" class="btn btn-sm btn-light btn-prev">↑</button>' +
            '<button type="button" class="btn btn-sm btn-light btn-next">↓</button>' +
            '<button type="button" class="btn btn-sm btn-light btn-close">✕</button>' +
            '</div>'
        );
        $(self.pane).append(box);
        self.search_box = box;

        var input = box.find('input');
        input.on('keydown', function (e) {
            if (e.key === 'Escape') {
                self.close_search();
            } else if (e.key === 'Enter') {
                self.searchAddon.findNext(input.val());
            }
            e.stopPropagation();
        });
        input.on('input', function () {
            if (self.searchAddon && input.val()) {
                self.searchAddon.findNext(input.val());
            }
        });
        box.find('.btn-prev').on('click', function () { self.searchAddon.findPrevious(input.val()); });
        box.find('.btn-next').on('click', function () { self.searchAddon.findNext(input.val()); });
        box.find('.btn-close').on('click', function () { self.close_search(); });
    };

    Session.prototype.open_search = function () {
        if (this.search_box) {
            this.search_box.show();
            this.search_box.find('input').focus();
        }
    };

    Session.prototype.close_search = function () {
        if (this.search_box) {
            this.search_box.hide();
            if (this.searchAddon) {
                this.searchAddon.clearDecorations();
            }
            this.focus();
        }
    };

    // ===== zmodem (sz/rz) =====
    Session.prototype.setup_zmodem = function () {
        var self = this;
        self.zsentry = new Zmodem.Sentry({
            to_terminal: function (octets) {},
            on_detect: function (detection) {
                var zsession = detection.confirm();
                var promise;
                if (zsession.type === 'receive') {
                    promise = self.download_file(zsession);
                } else {
                    promise = self.upload_file(zsession);
                }
                promise.catch(console.error.bind(console)).then(function () {});
            },
            on_retract: function () {},
            sender: function (octets) {
                if (self.sock) {
                    self.sock.send(new Uint8Array(octets));
                }
            },
        });
    };

    Session.prototype.upload_file = function (zsession) {
        var self = this;
        var uploadHtml = "<div>" +
            "<label class='upload-area' style='width:100%;text-align:center;' for='fupload'>" +
            "<input id='fupload' name='fupload' type='file' style='display:none;' multiple='true'>" +
            "<i class='fa fa-cloud-upload fa-3x'></i>" +
            "<br />" +
            t('upload.pick') +
            "</label>" +
            "<br />" +
            "<span style='margin-left:5px !important;' id='fileList'></span>" +
            "</div><div class='clearfix'></div>";

        var upload_dialog = bootbox.dialog({
            message: uploadHtml,
            title: t('upload.title'),
            buttons: {
                cancel: {
                    label: t('btn.close'),
                    className: 'btn-default',
                    callback: function () {
                        try {
                            // zsession 每 5s 发送一个 ZACK 包，强制置为 ZRINIT 以便关闭
                            zsession._last_header_name = "ZRINIT";
                            zsession.close();
                        } catch (e) {
                            console.log(e);
                        }
                    }
                },
            },
            closeButton: false,
        });

        function hideModal() {
            upload_dialog.modal('hide');
        }

        var file_el = document.getElementById('fupload');

        return new Promise(function (res) {
            file_el.onchange = function () {
                var files_obj = file_el.files;
                hideModal();
                var files = [];
                for (var i = 0; i < files_obj.length; i++) {
                    if (files_obj[i].size <= 2048 * 1024 * 1024) {
                        files.push(files_obj[i]);
                    } else {
                        toastr.warning(files_obj[i].name + t('msg.tooLargeUp'));
                    }
                }
                function forceClose() {
                    try {
                        zsession._last_header_name = "ZRINIT";
                        zsession.close();
                    } catch (e) {
                        console.log(e);
                    }
                }
                if (files.length === 0) {
                    forceClose();
                    return;
                } else if (files.length >= 25) {
                    toastr.warning(t('msg.tooMany'));
                    forceClose();
                    return;
                }
                Zmodem.Browser.send_block_files(zsession, files, {
                    on_offer_response: function (obj, xfer) {
                        if (!xfer) {
                            self.term_write(obj.name + ' was upload skipped\r\n');
                        }
                    },
                    on_progress: function (obj, xfer) {
                        self.update_progress(xfer, 'upload');
                    },
                    on_file_complete: function (obj) {
                        self.term_write('\r\n');
                        self.sock.send(JSON.stringify({ type: 'ignore', data: utf8_to_b64(obj.name + '(' + obj.size + ') was upload success') }));
                    },
                }).then(zsession.close.bind(zsession), console.error.bind(console)
                ).then(function () {
                    res();
                });
            };
        });
    };

    Session.prototype.update_progress = function (xfer, action) {
        var detail = xfer.get_details();
        var name = detail.name;
        var total = detail.size;
        var offset = xfer.get_offset();
        var percent;
        if (total === 0 || total === offset) {
            percent = 100;
        } else {
            percent = Math.round(offset / total * 100);
        }
        this.term_write('\r' + action + ' ' + name + ': ' + bytesHuman(offset) + ' ' + bytesHuman(total) + ' ' + percent + '% ');
    };

    Session.prototype.download_file = function (zsession) {
        var self = this;
        zsession.on('offer', function (xfer) {
            if (xfer.get_details().size > 2048 * 1024 * 1024) {
                xfer.skip();
                toastr.warning(xfer.get_details().name + t('msg.tooLargeDl'));
                return;
            }
            var FILE_BUFFER = [];
            xfer.on('input', function (payload) {
                self.update_progress(xfer, 'download');
                FILE_BUFFER.push(new Uint8Array(payload));
            });

            xfer.accept().then(
                function () {
                    Zmodem.Browser.save_to_disk(FILE_BUFFER, xfer.get_details().name);
                    self.term_write('\r\n');
                    self.sock.send(JSON.stringify({ type: 'ignore', data: utf8_to_b64(xfer.get_details().name + '(' + xfer.get_details().size + ') was download success') }));
                },
                console.error.bind(console)
            );
        });
        var promise = new Promise(function (res) {
            zsession.on('session_end', function () {
                res();
            });
        });
        zsession.start();
        return promise;
    };

    // ===== 连接 =====
    Session.prototype.connect = function (is_reconnect) {
        var self = this;
        self.state = CONNECTING;
        self.closed_normally = false;
        if (is_reconnect) {
            toastr.info(t('msg.reconnect').replace('{t}', self.title).replace('{n}', self.reconnect_attempts));
        }

        $.ajax({
            url: $('#connect').attr('action'),
            type: 'post',
            data: self.form_data,
            cache: false,
            contentType: false,
            processData: false,
            complete: function (resp) {
                self.on_connect_response(resp, is_reconnect);
            }
        });
    };

    Session.prototype.on_connect_response = function (resp, is_reconnect) {
        var self = this;
        if (resp.status !== 200) {
            self.state = DISCONNECTED;
            log_status(resp.status + ': ' + resp.statusText, !is_reconnect);
            if (is_reconnect) {
                self.schedule_reconnect();
            }
            return;
        }

        var msg = resp.responseJSON;
        if (!msg.id) {
            self.state = DISCONNECTED;
            log_status(msg.status, !is_reconnect);
            if (is_reconnect) {
                self.schedule_reconnect();
            }
            return;
        }

        self.id = msg.id;
        // 只有全新连接才重置重连计数，重连场景保留计数以便达到上限后停止
        if (!is_reconnect) {
            self.reconnect_attempts = 0;
        }

        if (msg.encoding) {
            if (!self.set_encoding(msg.encoding)) {
                self.set_encoding('utf-8');
            }
        }

        // 首次连接：先切换视图（终端容器必须可见，否则 xterm 尺寸计算错误），再初始化终端
        if (!self.term) {
            show_term_view();
            self.setup_term();
            self.activate();
        }

        var ws_url = window.location.href.split(/\?|#/, 1)[0].replace('http', 'ws');
        var join = (ws_url[ws_url.length - 1] === '/' ? '' : '/');
        var url = ws_url + join + 'connect?id=' + msg.id;

        var sock = new window.WebSocket(url, ['webssh']);
        sock.binaryType = 'arraybuffer';
        self.sock = sock;

        // 重建 zmodem 绑定
        self.setup_zmodem();

        sock.onopen = function () {
            self.state = CONNECTED;
            self.resized = false;
            self.fit();
            self.focus();
            title_element.text = url_opts_data.title || self.title;
            if (url_opts_data.command) {
                setTimeout(function () {
                    self.send_stdin(url_opts_data.command + '\r');
                }, 500);
            }
        };

        sock.onmessage = function (recv) {
            if (typeof recv.data === 'object') {
                self.zsentry.consume(recv.data);
            } else {
                try {
                    var msg = JSON.parse(recv.data);
                    switch (msg.type) {
                        case 'stdout':
                        case 'stderr':
                            self.term_write(b64_to_utf8(msg.data));
                            break;
                        case 'console':
                            console.log(b64_to_utf8(msg.data));
                            break;
                        case 'alert':
                            toastr.warning(b64_to_utf8(msg.data));
                            break;
                        case 'closed':
                            // 服务端告知会话正常结束（shell exit / 命令完成），不重连
                            self.closed_normally = true;
                            break;
                        default:
                            console.log('unsupport type msg', msg);
                    }
                } catch (e) {
                    console.log('unsupport data', recv.data);
                }
            }
        };

        sock.onerror = function (e) {
            console.error(e);
        };

        sock.onclose = function (e) {
            console.log('session closed', self.title, e);
            // 已被新的连接替换（重连场景），忽略旧 socket 的关闭事件
            if (self.sock !== sock) {
                return;
            }
            self.state = DISCONNECTED;
            self.sock = undefined;
            if (self.user_closed || self.closed_normally) {
                self.dispose();
                return;
            }

            // 标题与状态更新
            if (active_session === self) {
                title_element.text = default_title;
            }

            if (!is_reconnect_safe(self)) {
                self.dispose();
                return;
            }

            // 断线自动重连
            self.schedule_reconnect();
        };

        function is_reconnect_safe(s) {
            // 会话已被用户关闭时不再重连
            return !s.user_closed && sessions.indexOf(s) !== -1;
        }
    };

    Session.prototype.schedule_reconnect = function () {
        var self = this;
        if (self.user_closed) {
            return;
        }
        self.reconnect_attempts += 1;
        if (self.reconnect_attempts > MAX_RECONNECT) {
            toastr.error(self.title + t('msg.disconnectFail'));
            log_status('Connection lost: ' + self.title, true);
            return;
        }
        var delay = 2000 * self.reconnect_attempts;
        setTimeout(function () {
            if (!self.user_closed && sessions.indexOf(self) !== -1) {
                self.connect(true);
            }
        }, delay);
    };

    Session.prototype.dispose = function () {
        var self = this;
        self.user_closed = true;
        if (self.sock) {
            try { self.sock.close(1000); } catch (e) {}
            self.sock = undefined;
        }
        if (self.term) {
            try { self.term.dispose(); } catch (e) {}
            self.term = undefined;
        }
        self.tab.remove();
        self.pane.remove();
        var idx = sessions.indexOf(self);
        if (idx !== -1) {
            sessions.splice(idx, 1);
        }
        if (active_session === self) {
            active_session = null;
        }
        // 无会话时回到表单视图
        if (sessions.length === 0) {
            show_form_view();
        } else if (active_session === null) {
            sessions[sessions.length - 1].activate();
        }
    };

    function show_term_view() {
        form_view.addClass('hide');
        form_status_wrap.addClass('hide');
        term_view.removeClass('hide');
        // 终端模式下锁定页面滚动，滚动交给 xterm 自身回滚区，避免出现双重滚动条
        $('body').addClass('term-mode');
    }

    function show_form_view() {
        term_view.addClass('hide');
        form_view.removeClass('hide');
        form_status_wrap.removeClass('hide');
        status.html('');
        title_element.text = default_title;
        $('body').removeClass('term-mode');
    }

    // ==========================================================================
    // SFTP 面板开关
    // ==========================================================================

    $('#tab-new').on('click', function () {
        show_form_view();
    });

    // ==========================================================================
    // SFTP 文件管理
    // ==========================================================================
    var sftp_panel = $('#sftp-panel');
    var sftp_path_input = $('#sftp-path');

    $('#sftp-toggle').on('click', function () {
        if (!active_session || !active_session.id) {
            toastr.warning(t('msg.noSession'));
            return;
        }
        if (sftp_panel.hasClass('hide')) {
            sftp_panel.removeClass('hide');
            if (!sftp_path_input.val()) {
                sftp_list('');
            }
        } else {
            sftp_panel.addClass('hide');
        }
    });

    $('#sftp-close').on('click', function () {
        sftp_panel.addClass('hide');
    });

    function sftp_url(action, params) {
        var query = [];
        $.each(params, function (k, v) {
            query.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
        });
        return action + '?' + query.join('&');
    }

    function sftp_err(resp) {
        if (resp.status === 401) {
            toastr.error(t('msg.authFailed'));
        } else {
            toastr.error(t('msg.sftpFail') + (resp.responseText || resp.statusText));
        }
    }

    function sftp_list(path) {
        if (!active_session || !active_session.id) {
            return;
        }
        var sid = active_session.id;
        $.ajax({
            url: sftp_url('/sftp/list', { id: sid, path: path }),
            type: 'get',
            dataType: 'json'
        }).done(function (res) {
            sftp_path_input.val(res.path);
            render_sftp_list(res.items);
        }).fail(function (resp) {
            sftp_err(resp);
        });
    }

    function render_sftp_list(items) {
        var sid = active_session.id;
        var rows = '';
        $.each(items, function (i, item) {
            var full = sftp_path_input.val().replace(/\/$/, '') + '/' + item.name;
            var actions = '';
            if (!item.isdir) {
                actions += '<button type="button" class="btn btn-xs btn-primary btn-sftp-dl" data-path="' + full + '">' + t('btn.download') + '</button> ';
            }
            actions += '<button type="button" class="btn btn-xs btn-default btn-sftp-ren" data-path="' + full + '">' + t('btn.rename') + '</button> ';
            actions += '<button type="button" class="btn btn-xs btn-danger btn-sftp-del" data-path="' + full + '">' + t('btn.delete') + '</button>';
            rows += '<tr>' +
                '<td class="sftp-name ' + (item.isdir ? 'sftp-dir' : 'sftp-file') + '" data-path="' + full + '" data-isdir="' + item.isdir + '">' +
                (item.isdir ? '📁 ' : '📄 ') + item.name + '</td>' +
                '<td>' + (item.isdir ? '-' : bytesHuman(item.size)) + '</td>' +
                '<td>' + item.mode + '</td>' +
                '<td>' + new Date(item.modtime).toLocaleString() + '</td>' +
                '<td>' + actions + '</td>' +
                '</tr>';
        });
        $('#sftp-list').html(
            '<table class="table table-striped table-hover"><thead><tr>' +
            '<th>' + t('th.name') + '</th><th>' + t('th.size') + '</th><th>' + t('th.perm') + '</th><th>' + t('th.mtime') + '</th><th>' + t('th.actions') + '</th>' +
            '</tr></thead><tbody>' + rows + '</tbody></table>'
        );

        // 目录/文件点击
        $('#sftp-list .sftp-name').off('click').on('click', function () {
            var p = $(this).data('path');
            if ($(this).data('isdir')) {
                sftp_list(p);
            } else {
                sftp_download(p);
            }
        });
        $('#sftp-list .btn-sftp-dl').off('click').on('click', function () {
            sftp_download($(this).data('path'));
        });
        $('#sftp-list .btn-sftp-del').off('click').on('click', function () {
            var p = $(this).data('path');
            if (!confirm(t('msg.confirmDelete') + p + ' ?')) {
                return;
            }
            $.post(sftp_url('/sftp/delete', { id: active_session.id }), { id: active_session.id, path: p })
                .done(function () { sftp_list(sftp_path_input.val()); })
                .fail(function (resp) { sftp_err(resp); });
        });
        $('#sftp-list .btn-sftp-ren').off('click').on('click', function () {
            var p = $(this).data('path');
            var newName = prompt(t('prompt.newName'), p.split('/').pop());
            if (!newName) {
                return;
            }
            var parent = p.split('/').slice(0, -1).join('/');
            $.post(sftp_url('/sftp/rename', { id: active_session.id }), {
                id: active_session.id,
                from: p,
                to: parent + '/' + newName
            }).done(function () { sftp_list(sftp_path_input.val()); })
              .fail(function (resp) { sftp_err(resp); });
        });
    }

    function sftp_download(path) {
        if (!active_session || !active_session.id) {
            return;
        }
        var url = sftp_url('/sftp/get', { id: active_session.id, path: path });
        fetch(url).then(function (resp) {
            if (!resp.ok) {
                throw new Error(resp.status + ' ' + resp.statusText);
            }
            var disposition = resp.headers.get('Content-Disposition') || '';
            var match = disposition.match(/filename\*=UTF-8''([^;]+)/);
            var name = match ? decodeURIComponent(match[1]) : path.split('/').pop();
            return resp.blob().then(function (blob) {
                var a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = name;
                document.body.appendChild(a);
                a.click();
                setTimeout(function () {
                    URL.revokeObjectURL(a.href);
                    a.remove();
                }, 1000);
            });
        }).catch(function (e) {
            toastr.error(t('msg.downloadFail') + e.message);
        });
    }

    $('#sftp-go').on('click', function () { sftp_list(sftp_path_input.val()); });
    $('#sftp-path').on('keydown', function (e) {
        if (e.key === 'Enter') {
            sftp_list(sftp_path_input.val());
        }
    });
    $('#sftp-up').on('click', function () {
        var p = sftp_path_input.val().replace(/\/$/, '');
        var parent = p.split('/').slice(0, -1).join('/') || '/';
        sftp_list(parent);
    });
    $('#sftp-refresh').on('click', function () { sftp_list(sftp_path_input.val()); });
    $('#sftp-mkdir').on('click', function () {
        if (!active_session || !active_session.id) {
            return;
        }
        var name = prompt(t('prompt.dirname'));
        if (!name) {
            return;
        }
        var p = sftp_path_input.val().replace(/\/$/, '') + '/' + name;
        $.post(sftp_url('/sftp/mkdir', { id: active_session.id }), { id: active_session.id, path: p })
            .done(function () { sftp_list(sftp_path_input.val()); })
            .fail(function (resp) { sftp_err(resp); });
    });
    $('#sftp-upload-btn').on('click', function () {
        $('#sftp-upload').val('').click();
    });

    // 新建文件：弹窗输入文本内容后上传（内容为空也会创建空文件）
    $('#sftp-newfile').on('click', function () {
        if (!active_session || !active_session.id) {
            toastr.warning(t('msg.noActiveSession'));
            return;
        }
        var name = prompt(t('prompt.filename'));
        if (!name) {
            return;
        }
        open_sftp_text_editor(name);
    });

    function open_sftp_text_editor(filename) {
        $('#sftp-editor').remove();
        var $ed = $(
            '<div id="sftp-editor">' +
            '  <div class="sftp-editor-box">' +
            '    <div class="sftp-editor-head">' + t('editor.title') + $('<i>').text(filename).html() + '</div>' +
            '    <textarea id="sftp-editor-text" placeholder="' + t('ph.editor') + '" spellcheck="false"></textarea>' +
            '    <div class="sftp-editor-foot">' +
            '      <button type="button" class="btn btn-sm btn-secondary" id="sftp-editor-cancel">' + t('btn.cancel') + '</button>' +
            '      <button type="button" class="btn btn-sm btn-primary" id="sftp-editor-ok">' + t('btn.okUpload') + '</button>' +
            '    </div>' +
            '  </div>' +
            '</div>'
        );
        $('body').append($ed);
        $('#sftp-editor-text').focus();

        $('#sftp-editor-cancel').on('click', function () {
            $ed.remove();
        });
        $('#sftp-editor').on('click', function (e) {
            if (e.target === this) {
                $ed.remove();
            }
        });
        $('#sftp-editor-ok').on('click', function () {
            var content = $('#sftp-editor-text').val();
            $ed.remove();
            upload_sftp_text_file(filename, content);
        });
    }

    function upload_sftp_text_file(filename, content) {
        var base = sftp_path_input.val().replace(/\/$/, '');
        var form = new FormData();
        // 内容为空时也生成 0 字节文件
        form.append('file', new File([new Blob([content], {type: 'text/plain'})], filename, {type: 'text/plain'}));
        form.append('id', active_session.id);
        form.append('path', base + '/' + filename);

        $.ajax({
            url: '/sftp/put',
            type: 'POST',
            data: form,
            processData: false,
            contentType: false
        }).done(function () {
            toastr.success(t('msg.fileCreated') + filename);
            sftp_list(sftp_path_input.val());
        }).fail(function (resp) {
            sftp_err(resp);
        });
    }

    $('#sftp-upload').on('change', function () {
        var files = this.files;
        if (!files.length || !active_session || !active_session.id) {
            return;
        }
        var base = sftp_path_input.val().replace(/\/$/, '');
        var sid = active_session.id;
        var i = 0;

        function uploadNext() {
            if (i >= files.length) {
                toastr.success(t('msg.allUploaded'));
                sftp_list(sftp_path_input.val());
                return;
            }
            var file = files[i];
            var form = new FormData();
            form.append('id', sid);
            form.append('path', base + '/' + file.name);
            form.append('file', file);

            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/sftp/put', true);
            xhr.upload.onprogress = function (e) {
                if (e.lengthComputable) {
                    var percent = Math.round(e.loaded / e.total * 100);
                    toastr.clear();
                    toastr.info(t('msg.uploading') + file.name + ': ' + percent + '%');
                }
            };
            xhr.onload = function () {
                if (xhr.status !== 200) {
                    toastr.error(t('msg.uploading') + file.name + t('msg.uploadFail') + xhr.responseText);
                }
                i += 1;
                uploadNext();
            };
            xhr.onerror = function () {
                toastr.error(t('msg.uploading') + file.name + t('msg.uploadFailShort'));
                i += 1;
                uploadNext();
            };
            xhr.send(form);
        }

        uploadNext();
    });

    // ==========================================================================
    // 连接表单
    // ==========================================================================
    function wrap_object(opts) {
        var obj = {};

        obj.get = function(attr) {
            return opts[attr] || '';
        };

        obj.set = function(attr, val) {
            opts[attr] = val;
        };

        return obj;
    }


    function clean_data(data) {
        var i, attr, val;
        var attrs = form_keys.concat(['privatekey', 'passphrase']);

        for (i = 0; i < attrs.length; i++) {
            attr = attrs[i];
            val = data.get(attr);
            if (typeof val === 'string') {
                data.set(attr, val.trim());
            }
        }
    }


    function validate_form_data(data) {
        clean_data(data);

        var hostname = data.get('hostname'),
            port = data.get('port'),
            username = data.get('username'),
            pk = data.get('privatekey'),
            result = {
                valid: false,
                data: data,
                title: ''
            },
            errors = [], size;

        if (!hostname) {
            errors.push('Value of hostname is required.');
        } else {
            if (!hostname_tester.test(hostname)) {
                errors.push('Invalid hostname: ' + hostname);
            }
        }

        if (!port) {
            port = 22;
            data.set('port', port);
        } else {
            if (!(port > 0 && port < 65535)) {
                errors.push('Invalid port: ' + port);
            }
        }

        if (!username) {
            errors.push('Value of username is required.');
        }

        if (pk) {
            size = pk.size || pk.length;
            if (size > key_max_size) {
                errors.push('Invalid private key: ' + (pk.name || ''));
            }
        }

        if (!errors.length || debug) {
            result.valid = true;
            result.title = username + '@' + hostname + ':'  + port;
        }
        result.errors = errors;

        return result;
    }

    // Fix empty input file ajax submission error for safari 11.x
    function disable_file_inputs(inputs) {
        var i, input;

        for (i = 0; i < inputs.length; i++) {
            input = inputs[i];
            if (input.files.length === 0) {
                input.setAttribute('disabled', '');
            }
        }
    }


    function enable_file_inputs(inputs) {
        var i;

        for (i = 0; i < inputs.length; i++) {
            inputs[i].removeAttribute('disabled');
        }
    }


    function connect_without_options() {
        // use data from the form
        var form = document.querySelector(form_id),
            inputs = form.querySelectorAll('input[type="file"]'),
            url = form.action,
            data, pk;

        disable_file_inputs(inputs);
        data = new FormData(form);
        pk = data.get('privatekey');
        enable_file_inputs(inputs);

        var result = validate_form_data(data);
        if (!result.valid) {
            log_status(result.errors.join('\n'));
            return;
        }

        if (pk && pk.size && !debug) {
            read_file_as_text(pk, function(text) {
                if (text === undefined) {
                    log_status('Invalid private key: ' + pk.name);
                } else {
                    start_session(data, result.title);
                }
            });
        } else {
            start_session(data, result.title);
        }

        return result;
    }


    function connect_with_options(data) {
        // use data from the arguments
        var form = document.querySelector(form_id),
            url = data.url || form.action,
            _xsrf = form.querySelector('input[name="_xsrf"]');

        var result = validate_form_data(wrap_object(data));
        if (!result.valid) {
            log_status(result.errors.join('\n'));
            return;
        }

        data.term = term_type.val();
        if (_xsrf) {
            data._xsrf = _xsrf.value;
        }
        if (event_origin) {
            data._origin = event_origin;
        }

        var fd = new FormData();
        $.each(data, function (k, v) {
            if (v !== undefined && v !== null) {
                fd.append(k, v);
            }
        });
        start_session(fd, result.title);

        return result;
    }


    function start_session(form_data, title) {
        status.text('');
        button.prop('disabled', false);
        waiter.show();

        // 单会话模式（默认）：同一页面仅保留一个会话，新连接会替换旧会话
        if (!FEATURES.tabs) {
            while (sessions.length > 0) {
                sessions[0].dispose();
            }
        }

        var session = new Session(form_data, title);
        sessions.push(session);
        session.connect(false);
        waiter.hide();
    }


    function connect(hostname, port, username, password, privatekey, passphrase, totp) {
        // for console use
        var result, opts;

        if (hostname === undefined) {
            result = connect_without_options();
        } else {
            if (typeof hostname === 'string') {
                opts = {
                    hostname: hostname,
                    port: port,
                    username: username,
                    password: password,
                    privatekey: privatekey,
                    passphrase: passphrase,
                    totp: totp
                };
            } else {
                opts = hostname;
            }

            result = connect_with_options(opts);
        }

        if (result) {
            validated_form_data = result.data;
            store_items(fields, result.data);
        }
    }

    wssh.connect = connect;

    $(form_id).submit(function(event){
        event.preventDefault();
        connect();
    });


    function cross_origin_connect(event)
    {
        console.log(event.origin);
        var prop = 'connect',
            args;

        try {
            args = JSON.parse(event.data);
        } catch (SyntaxError) {
            args = event.data.split('|');
        }

        if (!Array.isArray(args)) {
            args = [args];
        }

        try {
            event_origin = event.origin;
            wssh[prop].apply(wssh, args);
        } finally {
            event_origin = undefined;
        }
    }

    window.addEventListener('message', cross_origin_connect, false);

    if (document.fonts) {
        document.fonts.ready.then(
            function () {
                if (custom_font_is_loaded() === false) {
                    document.body.style.fontFamily = custom_font.family;
                }
            }
        );
    }

    function custom_font_is_loaded() {
        if (!custom_font) {
            console.log('No custom font specified.');
        } else {
            console.log('Status of custom font ' + custom_font.family + ': ' + custom_font.status);
            if (custom_font.status === 'loaded') {
                return true;
            }
            if (custom_font.status === 'unloaded') {
                return false;
            }
        }
    }

    // 窗口尺寸变化：只调整当前激活会话
    $(window).resize(function () {
        if (active_session && active_session.term) {
            active_session.resize_to_window();
        }
    });

    parse_url_data(
        decode_uri(window.location.search.substring(1)) + '&' + decode_uri(window.location.hash.substring(1)),
        form_keys, opts_keys, url_form_data, url_opts_data
    );

    if (url_opts_data.term) {
        term_type.val(url_opts_data.term);
    }

    if (url_form_data.password === null) {
        log_status('Password via url must be encoded in base64.');
    } else {
        if (get_object_length(url_form_data)) {
            waiter.show();
            connect(url_form_data);
        } else {
            restore_items(fields);
            form_view.removeClass('hide');
        }
    }

});

"""
Nuclei 可视化扫描 Tab  — v1.7
唐门-暗之器
优化：
  1. 模板目录用后台线程异步加载，带实时进度，不卡主线程
  2. 进度条空闲时不动（仅扫描时切换不确定模式）
  3. GUI 文字截断问题修复（合理宽度 / elide 策略）
  4. 额外选项改为下拉框 + 快捷勾选（参照 nuclei 官方文档）
  5. v1.6: 全局按钮字体 12px + padding，所有按钮文字清晰可读
  6. v1.7: 漏洞统计排除 INFO 级别，只统计真实安全问题（critical/high/medium/low）
"""
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSplitter, QTreeWidget, QTreeWidgetItem,
    QPlainTextEdit, QGroupBox, QGridLayout, QSpinBox,
    QCheckBox, QComboBox, QProgressBar, QFileDialog,
    QMessageBox, QMenu, QDialog, QDialogButtonBox,
    QTextEdit, QHeaderView, QInputDialog, QTabWidget,
    QFrame, QSizePolicy, QScrollArea, QFormLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QColor, QAction, QIcon, QTextCursor

sys.path.insert(0, str(Path(__file__).parent.parent / "fofa-scan"))
sys.path.insert(0, str(Path(__file__).parent))

from nuclei_runner import NucleiRunner


class TemplateLoader(QThread):
    """
    在后台线程中递归扫描目录，收集所有 .yaml/.yml 文件。
    每扫描到一个文件就发一次 progress_signal，完成后发 finished_signal。
    """
    progress_signal = pyqtSignal(int, str)
    finished_signal = pyqtSignal(list)

    def __init__(self, root_dir: str, parent=None):
        super().__init__(parent)
        self.root_dir = root_dir
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        results = []
        count = 0
        root = Path(self.root_dir)
        try:
            for yaml_path in self._iter_yaml(root):
                if self._stop:
                    break
                rel = yaml_path.relative_to(root)
                results.append((list(rel.parts), str(yaml_path)))
                count += 1
                if count % 50 == 0:
                    self.progress_signal.emit(count, yaml_path.parent.name)
        except Exception as e:
            pass
        self.finished_signal.emit(results)

    def _iter_yaml(self, path: Path):
        try:
            entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except PermissionError:
            return
        for entry in entries:
            if entry.name.startswith("."):
                continue
            if entry.is_dir():
                yield from self._iter_yaml(entry)
            elif entry.suffix.lower() in (".yaml", ".yml"):
                yield entry


class TemplateEditorDialog(QDialog):
    """YAML 模板编辑器"""

    def __init__(self, filepath: str, parent=None):
        super().__init__(parent)
        self.filepath = filepath
        self.setWindowTitle("模板编辑器 — %s" % Path(filepath).name)
        self.setMinimumSize(960, 700)
        base = parent.styleSheet() if parent else ""
        self.setStyleSheet(base + """
            QPushButton { font-size: 12px; padding: 4px 10px; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        path_layout = QHBoxLayout()
        path_lbl = QLabel("文件:")
        path_lbl.setStyleSheet("color:#00aa33;")
        path_lbl.setFixedWidth(36)
        path_layout.addWidget(path_lbl)
        self.path_edit = QLineEdit(filepath)
        self.path_edit.setReadOnly(True)
        self.path_edit.setStyleSheet(
            "background:#0f0f0f;border:1px solid #003300;color:#555555;"
        )
        path_layout.addWidget(self.path_edit)
        layout.addLayout(path_layout)

        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", 11))
        self.editor.setStyleSheet(
            "background:#0a0a0a;border:1px solid #00ff41;"
            "color:#00ff41;font-family:Consolas,monospace;"
        )
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
        except Exception as e:
            self.editor.setPlainText("# 读取文件失败: %s" % e)

        layout.addWidget(self.editor)

        self.status_lbl = QLabel("就绪")
        self.status_lbl.setStyleSheet("color:#555555;font-size:11px;")
        layout.addWidget(self.status_lbl)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        save_btn = QPushButton("💾 保存")
        save_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        save_btn.setMinimumWidth(64)
        save_btn.setFixedHeight(26)
        save_btn.clicked.connect(self._save)
        btn_layout.addWidget(save_btn)
        close_btn = QPushButton("关闭")
        close_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        close_btn.setMinimumWidth(52)
        close_btn.setFixedHeight(26)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write(self.editor.toPlainText())
            self.status_lbl.setText(
                "✅ 已保存  %s" % datetime.now().strftime("%H:%M:%S")
            )
        except Exception as e:
            self.status_lbl.setText("❌ 保存失败: %s" % e)


class TemplateTreeWidget(QWidget):
    """左侧模板浏览树（后台线程加载，不卡主线程）"""

    selection_changed = pyqtSignal(list)
    load_progress = pyqtSignal(int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._template_dir = ""
        self._loader: Optional[TemplateLoader] = None
        self._is_loading = False
        self._init_ui()

    def _init_ui(self):
        self.setStyleSheet("""
            QPushButton { font-size: 12px; padding: 4px 8px; }
            QLineEdit { font-size: 12px; }
            QLabel { font-size: 12px; }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        bar = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 搜索模板名称...")
        self.search_edit.textChanged.connect(self._filter_tree)
        bar.addWidget(self.search_edit)

        self.reload_btn = QPushButton("↻ 重载")
        self.reload_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.reload_btn.setMinimumWidth(80)
        self.reload_btn.setFixedHeight(26)
        self.reload_btn.setToolTip("重新加载模板目录")
        self.reload_btn.clicked.connect(self.reload)
        bar.addWidget(self.reload_btn)
        layout.addLayout(bar)

        self.load_bar = QProgressBar()
        self.load_bar.setTextVisible(True)
        self.load_bar.setMaximum(0)
        self.load_bar.setFixedHeight(14)
        self.load_bar.setStyleSheet(
            "QProgressBar{background:#0a0a0a;border:1px solid #003300;"
            "color:#00ff41;font-size:10px;border-radius:2px;}"
            "QProgressBar::chunk{background:#00ff41;}"
        )
        self.load_bar.setFormat("正在扫描模板...")
        self.load_bar.setVisible(False)
        layout.addWidget(self.load_bar)

        sel_bar = QHBoxLayout()
        sel_bar.setSpacing(4)
        all_btn = QPushButton("✔ 全选")
        all_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        all_btn.setMinimumWidth(72)
        all_btn.setFixedHeight(24)
        all_btn.clicked.connect(self._check_all)
        sel_bar.addWidget(all_btn)
        none_btn = QPushButton("✖ 全不选")
        none_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        none_btn.setMinimumWidth(78)
        none_btn.setFixedHeight(24)
        none_btn.clicked.connect(self._uncheck_all)
        sel_bar.addWidget(none_btn)
        self.count_lbl = QLabel("0 个模板")
        self.count_lbl.setStyleSheet("color:#555555;font-size:11px;")
        sel_bar.addWidget(self.count_lbl)
        sel_bar.addStretch()
        layout.addLayout(sel_bar)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("模板列表")
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.setStyleSheet(
            "QTreeWidget{background:#0f0f0f;border:1px solid #00ff41;"
            "color:#00ff41;}"
            "QTreeWidget::item:selected{background:#00ff41;color:#0a0a0a;}"
            "QTreeWidget::item:hover{background:#1a3a1a;}"
        )
        layout.addWidget(self.tree)

    def set_template_dir(self, path: str):
        self._template_dir = path
        self.reload()

    def reload(self):
        if self._is_loading:
            if self._loader:
                self._loader.stop()
                self._loader.wait(200)
        self.tree.blockSignals(True)
        self.tree.clear()
        self.tree.blockSignals(False)
        self.count_lbl.setText("加载中...")
        if not self._template_dir or not Path(self._template_dir).exists():
            self.count_lbl.setText("目录无效")
            return

        self._is_loading = True
        self.load_bar.setVisible(True)
        self.load_bar.setFormat("正在扫描模板目录...")
        self.load_bar.setMaximum(0)
        self.reload_btn.setEnabled(False)

        self._loader = TemplateLoader(self._template_dir)
        self._loader.progress_signal.connect(self._on_load_progress)
        self._loader.finished_signal.connect(self._on_load_finished)
        self._loader.start()

    def get_checked_templates(self) -> List[str]:
        result = []
        self._collect_checked(self.tree.invisibleRootItem(), result)
        return result

    def _on_load_progress(self, count: int, dir_name: str):
        self.load_bar.setFormat("已扫描 %d 个模板... (%s)" % (count, dir_name))
        self.load_progress.emit(count, dir_name)

    def _on_load_finished(self, file_list: list):
        self._is_loading = False
        self.load_bar.setVisible(False)
        self.reload_btn.setEnabled(True)

        self.tree.blockSignals(True)
        dir_nodes = {}

        for parts, abs_path in file_list:
            for depth in range(1, len(parts)):
                key = tuple(parts[:depth])
                if key not in dir_nodes:
                    parent_key = tuple(parts[:depth - 1])
                    parent_item = (
                        dir_nodes[parent_key]
                        if parent_key in dir_nodes
                        else self.tree.invisibleRootItem()
                    )
                    node = QTreeWidgetItem(parent_item)
                    node.setText(0, parts[depth - 1])
                    node.setFlags(
                        node.flags()
                        | Qt.ItemFlag.ItemIsUserCheckable
                        | Qt.ItemFlag.ItemIsAutoTristate
                    )
                    node.setCheckState(0, Qt.CheckState.Unchecked)
                    dir_nodes[key] = node

            parent_key = tuple(parts[:-1])
            parent_item = (
                dir_nodes[parent_key]
                if parent_key in dir_nodes
                else self.tree.invisibleRootItem()
            )
            leaf = QTreeWidgetItem(parent_item)
            leaf.setText(0, parts[-1])
            leaf.setFlags(leaf.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            leaf.setCheckState(0, Qt.CheckState.Unchecked)
            leaf.setData(0, Qt.ItemDataRole.UserRole, abs_path)

        for key, node in dir_nodes.items():
            dir_path = str(Path(self._template_dir) / Path(*key))
            node.setData(0, Qt.ItemDataRole.UserRole, dir_path)

        self.tree.blockSignals(False)

        total = len(file_list)
        self.count_lbl.setText("%d 个模板" % total)

        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            root.child(i).setExpanded(True)

    def _collect_checked(self, parent, result: list):
        for i in range(parent.childCount()):
            child = parent.child(i)
            path = child.data(0, Qt.ItemDataRole.UserRole)
            if path and child.checkState(0) == Qt.CheckState.Checked:
                p = Path(path)
                if p.is_file() and p.suffix.lower() in (".yaml", ".yml"):
                    result.append(str(p))
            self._collect_checked(child, result)

    def _check_all(self):
        self._set_all_check(self.tree.invisibleRootItem(), Qt.CheckState.Checked)

    def _uncheck_all(self):
        self._fast_uncheck_all()

    def _fast_uncheck_all(self):
        self.tree.blockSignals(True)
        stack = [self.tree.invisibleRootItem()]
        while stack:
            parent = stack.pop()
            for i in range(parent.childCount()):
                child = parent.child(i)
                if child.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                    if child.checkState(0) != Qt.CheckState.Unchecked:
                        child.setCheckState(0, Qt.CheckState.Unchecked)
                if child.childCount():
                    stack.append(child)
        self.tree.blockSignals(False)
        self.selection_changed.emit([])

    def _set_all_check(self, parent, state):
        self.tree.blockSignals(True)
        stack = [parent]
        while stack:
            node = stack.pop()
            for i in range(node.childCount()):
                child = node.child(i)
                if child.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                    child.setCheckState(0, state)
                if child.childCount():
                    stack.append(child)
        self.tree.blockSignals(False)
        self.selection_changed.emit(self.get_checked_templates())

    def _on_item_changed(self, item, col):
        self.selection_changed.emit(self.get_checked_templates())

    def _filter_tree(self, text: str):
        text = text.strip().lower()

        def _hide_or_show(parent) -> bool:
            any_visible = False
            for i in range(parent.childCount()):
                child = parent.child(i)
                if child.childCount() > 0:
                    visible = _hide_or_show(child)
                    child.setHidden(not visible)
                    if visible:
                        any_visible = True
                else:
                    match = (not text) or (text in child.text(0).lower())
                    child.setHidden(not match)
                    if match:
                        any_visible = True
            return any_visible

        _hide_or_show(self.tree.invisibleRootItem())

    def _context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if item is None:
            return
        path = item.data(0, Qt.ItemDataRole.UserRole)
        if not path:
            return
        p = Path(path)

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#0a0a0a;border:1px solid #00ff41;color:#00ff41;}"
            "QMenu::item:selected{background:#00ff41;color:#0a0a0a;}"
        )

        if p.is_file():
            use_act = menu.addAction("✅ 使用该模板（单独勾选）")
            edit_act = menu.addAction("✏️ 编辑该模板")
            rename_act = menu.addAction("📝 重命名")
            menu.addSeparator()
            copy_act = menu.addAction("📋 复制路径")

            action = menu.exec(self.tree.viewport().mapToGlobal(pos))

            if action == use_act:
                self._uncheck_all()
                self.tree.blockSignals(True)
                item.setCheckState(0, Qt.CheckState.Checked)
                self.tree.blockSignals(False)
                self.selection_changed.emit(self.get_checked_templates())

            elif action == edit_act:
                dlg = TemplateEditorDialog(str(p), self)
                dlg.exec()

            elif action == rename_act:
                new_name, ok = QInputDialog.getText(
                    self, "重命名", "新文件名:", text=p.name
                )
                if ok and new_name.strip():
                    new_path = p.parent / new_name.strip()
                    try:
                        p.rename(new_path)
                        item.setText(0, new_name.strip())
                        item.setData(0, Qt.ItemDataRole.UserRole, str(new_path))
                    except Exception as e:
                        QMessageBox.critical(self, "重命名失败", str(e))

            elif action == copy_act:
                from PyQt6.QtWidgets import QApplication
                QApplication.clipboard().setText(str(p))

        elif p.is_dir():
            check_dir_act = menu.addAction("✅ 勾选该目录所有模板")
            uncheck_dir_act = menu.addAction("☐ 取消该目录所有模板")
            action = menu.exec(self.tree.viewport().mapToGlobal(pos))
            if action == check_dir_act:
                self.tree.blockSignals(True)
                self._set_all_check(item, Qt.CheckState.Checked)
                self.tree.blockSignals(False)
                self.selection_changed.emit(self.get_checked_templates())
            elif action == uncheck_dir_act:
                self.tree.blockSignals(True)
                self._set_all_check(item, Qt.CheckState.Unchecked)
                self.tree.blockSignals(False)
                self.selection_changed.emit(self.get_checked_templates())


class NucleiTab(QWidget):
    """Nuclei 可视化扫描标签页"""

    request_switch_tab = pyqtSignal()

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.runner: Optional[NucleiRunner] = None
        self._scan_start_time: Optional[datetime] = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_timer)
        self._vuln_count = 0
        self._init_ui()
        self._load_config()

    def _init_ui(self):
        self.setStyleSheet("""
            QPushButton {
                font-size: 12px;
                padding-left: 8px;
                padding-right: 8px;
                padding-top: 4px;
                padding-bottom: 4px;
            }
            QLineEdit, QPlainTextEdit, QTextEdit {
                font-size: 12px;
            }
            QLabel {
                font-size: 12px;
            }
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        cfg_group = QGroupBox("【 Nuclei 配置 】")
        cfg_layout = QGridLayout()
        cfg_layout.setColumnStretch(1, 1)
        cfg_layout.setSpacing(6)

        lbl_exe = QLabel("Nuclei 路径:")
        lbl_exe.setMinimumWidth(76)
        cfg_layout.addWidget(lbl_exe, 0, 0)
        self.exe_edit = QLineEdit()
        self.exe_edit.setPlaceholderText("nuclei.exe 完整路径，如 C:/tools/nuclei.exe")
        cfg_layout.addWidget(self.exe_edit, 0, 1)
        browse_exe_btn = QPushButton("📂 浏览")
        browse_exe_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        browse_exe_btn.setMinimumWidth(88)
        browse_exe_btn.setFixedHeight(26)
        browse_exe_btn.clicked.connect(self._browse_exe)
        cfg_layout.addWidget(browse_exe_btn, 0, 2)
        save_cfg_btn = QPushButton("💾 保存配置")
        save_cfg_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        save_cfg_btn.setMinimumWidth(100)
        save_cfg_btn.setFixedHeight(26)
        save_cfg_btn.clicked.connect(self._save_config)
        cfg_layout.addWidget(save_cfg_btn, 0, 3)

        lbl_tmpl = QLabel("模板目录:")
        lbl_tmpl.setMinimumWidth(76)
        cfg_layout.addWidget(lbl_tmpl, 1, 0)
        self.tmpl_dir_edit = QLineEdit()
        self.tmpl_dir_edit.setPlaceholderText("nuclei-templates 目录路径")
        cfg_layout.addWidget(self.tmpl_dir_edit, 1, 1)
        browse_tmpl_btn = QPushButton("📂 浏览")
        browse_tmpl_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        browse_tmpl_btn.setMinimumWidth(88)
        browse_tmpl_btn.setFixedHeight(26)
        browse_tmpl_btn.clicked.connect(self._browse_tmpl_dir)
        cfg_layout.addWidget(browse_tmpl_btn, 1, 2)
        reload_tmpl_btn = QPushButton("↻ 加载模板")
        reload_tmpl_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        reload_tmpl_btn.setMinimumWidth(104)
        reload_tmpl_btn.setFixedHeight(26)
        reload_tmpl_btn.clicked.connect(self._reload_templates)
        cfg_layout.addWidget(reload_tmpl_btn, 1, 3)

        lbl_out = QLabel("结果输出:")
        lbl_out.setMinimumWidth(76)
        cfg_layout.addWidget(lbl_out, 2, 0)
        self.out_dir_edit = QLineEdit()
        self.out_dir_edit.setPlaceholderText("扫描结果保存目录（留空不保存文件）")
        cfg_layout.addWidget(self.out_dir_edit, 2, 1)
        browse_out_btn = QPushButton("📂 浏览")
        browse_out_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        browse_out_btn.setMinimumWidth(88)
        browse_out_btn.setFixedHeight(26)
        browse_out_btn.clicked.connect(self._browse_out_dir)
        cfg_layout.addWidget(browse_out_btn, 2, 2)

        self.tmpl_load_lbl = QLabel("就绪")
        self.tmpl_load_lbl.setStyleSheet("color:#555555;font-size:11px;")
        cfg_layout.addWidget(self.tmpl_load_lbl, 2, 3)

        cfg_group.setLayout(cfg_layout)
        root.addWidget(cfg_group)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("QSplitter::handle{background:#003300;}")

        left_panel = QWidget()
        left_panel.setMinimumWidth(220)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 4, 0)

        tmpl_group = QGroupBox("【 模板浏览 】")
        tmpl_v = QVBoxLayout(tmpl_group)
        tmpl_v.setContentsMargins(4, 6, 4, 4)
        self.tmpl_tree = TemplateTreeWidget()
        self.tmpl_tree.selection_changed.connect(self._on_template_selection)
        self.tmpl_tree.load_progress.connect(self._on_tmpl_load_progress)
        tmpl_v.addWidget(self.tmpl_tree)

        self.selected_count_lbl = QLabel("已选: 0 个模板")
        self.selected_count_lbl.setStyleSheet("color:#00aaff;font-size:11px;")
        tmpl_v.addWidget(self.selected_count_lbl)
        left_layout.addWidget(tmpl_group)
        splitter.addWidget(left_panel)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(4, 0, 0, 0)
        right_layout.setSpacing(5)

        tgt_group = QGroupBox("【 扫描目标 】")
        tgt_layout = QVBoxLayout(tgt_group)
        tgt_layout.setSpacing(4)

        tgt_input_row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("单个目标，如 http://192.168.1.1 或 example.com")
        tgt_input_row.addWidget(self.target_edit)
        load_txt_btn = QPushButton("📄 从文件加载")
        load_txt_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        load_txt_btn.setMinimumWidth(120)
        load_txt_btn.setFixedHeight(26)
        load_txt_btn.clicked.connect(self._load_targets_file)
        tgt_input_row.addWidget(load_txt_btn)
        clear_tgt_btn = QPushButton("🗑")
        clear_tgt_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        clear_tgt_btn.setMinimumWidth(32)
        clear_tgt_btn.setFixedHeight(26)
        clear_tgt_btn.setToolTip("清空目标列表")
        clear_tgt_btn.clicked.connect(self._clear_targets)
        tgt_input_row.addWidget(clear_tgt_btn)
        tgt_layout.addLayout(tgt_input_row)

        self.target_list = QPlainTextEdit()
        self.target_list.setPlaceholderText(
            "目标列表（每行一个 URL/IP/域名），也可通过 FOFA 模块一键导入..."
        )
        self.target_list.setFixedHeight(70)
        tgt_layout.addWidget(self.target_list)

        tgt_count_row = QHBoxLayout()
        self.tgt_count_lbl = QLabel("0 个目标")
        self.tgt_count_lbl.setStyleSheet("color:#555555;font-size:11px;")
        tgt_count_row.addWidget(self.tgt_count_lbl)
        tgt_count_row.addStretch()
        self.target_list.textChanged.connect(self._update_target_count)
        tgt_layout.addLayout(tgt_count_row)
        right_layout.addWidget(tgt_group)

        param_group = QGroupBox("【 扫描参数 】")
        param_group.setMaximumHeight(90)
        param_main = QVBoxLayout(param_group)
        param_main.setSpacing(4)
        param_main.setContentsMargins(8, 6, 8, 4)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("-proxy:"))
        self.proxy_combo = QComboBox()
        self.proxy_combo.setEditable(True)
        self.proxy_combo.addItems([
            "", "http://127.0.0.1:8080", "http://127.0.0.1:7890",
            "socks5://127.0.0.1:1080", "http://127.0.0.1:8888"
        ])
        self.proxy_combo.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.proxy_combo.setMinimumWidth(180)
        self.proxy_combo.setToolTip("HTTP/SOCKS5 代理地址（留空不使用）")
        row1.addWidget(self.proxy_combo)

        row1.addSpacing(12)

        row1.addWidget(QLabel("自定义:"))
        self.extra_args_edit = QLineEdit()
        self.extra_args_edit.setPlaceholderText(
            "如: -c 30 -timeout 15 -severity critical,high -no-httpx -stats"
        )
        self.extra_args_edit.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.extra_args_edit.setMinimumWidth(320)
        self.extra_args_edit.setToolTip(
            "直接输入 nuclei 额外参数（所有选项均在此输入，参数会原样传递给 nuclei）"
        )
        row1.addWidget(self.extra_args_edit)
        row1.addStretch()

        param_main.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("快捷:"))

        quick_params = [
            ("-no-httpx", "-no-httpx", "禁用 httpx 探测"),
            ("-stats", "-stats", "显示统计信息"),
            ("-silent", "-silent", "静默模式"),
            ("-follow-redirects", "-follow-redirects", "跟随重定向"),
            ("-headless", "-headless", "无头浏览器模板"),
        ]
        self._quick_btns = {}
        for flag, label, tip in quick_params:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setToolTip(tip)
            btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
            btn.setMinimumWidth(168)
            btn.setFixedHeight(24)
            self._quick_btns[flag] = btn
            row2.addWidget(btn)

        row2.addStretch()
        param_main.addLayout(row2)

        right_layout.addWidget(param_group)

        ctrl_layout = QHBoxLayout()

        self.simple_mode_cb = QCheckBox("⚡ 默认模式")
        self.simple_mode_cb.setChecked(True)
        self.simple_mode_cb.setToolTip(
            "勾选 = 最简命令（只传 -u/-t/-jsonl/-o，nuclei 使用自身默认参数）\n"
            "取消 = 应用下方自定义参数 + 快捷按钮 + proxy 的内容"
        )
        self.simple_mode_cb.setStyleSheet("color:#00ffcc;font-weight:bold;")
        ctrl_layout.addWidget(self.simple_mode_cb)

        ctrl_layout.addSpacing(12)

        self.start_btn = QPushButton("▶ 开始扫描")
        self.start_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.start_btn.setMinimumWidth(120)
        self.start_btn.setFixedHeight(28)
        self.start_btn.clicked.connect(self.start_scan)
        ctrl_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹ 停止扫描")
        self.stop_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.stop_btn.setMinimumWidth(120)
        self.stop_btn.setFixedHeight(28)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        ctrl_layout.addWidget(self.stop_btn)

        self.export_btn = QPushButton("💾 导出结果")
        self.export_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.export_btn.setMinimumWidth(108)
        self.export_btn.setFixedHeight(28)
        self.export_btn.clicked.connect(self._export_results)
        ctrl_layout.addWidget(self.export_btn)

        self.clear_btn = QPushButton("🗑 清空输出")
        self.clear_btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.clear_btn.setMinimumWidth(108)
        self.clear_btn.setFixedHeight(28)
        self.clear_btn.setMinimumWidth(100)
        self.clear_btn.clicked.connect(self._clear_output)
        ctrl_layout.addWidget(self.clear_btn)

        ctrl_layout.addStretch()

        self.elapsed_lbl = QLabel("00:00")
        self.elapsed_lbl.setStyleSheet(
            "color:#00aaff;font-size:12px;font-weight:bold;"
        )
        ctrl_layout.addWidget(self.elapsed_lbl)
        right_layout.addLayout(ctrl_layout)

        prog_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("就绪")
        self.progress_bar.setStyleSheet(
            "QProgressBar{background:#0a0a0a;border:1px solid #003300;"
            "color:#00ff41;font-size:11px;border-radius:3px;}"
            "QProgressBar::chunk{background:#00ff41;border-radius:3px;}"
        )
        prog_layout.addWidget(self.progress_bar, stretch=4)
        self.status_lbl = QLabel("就绪")
        self.status_lbl.setStyleSheet("color:#00ff41;font-weight:bold;")
        self.status_lbl.setMinimumWidth(80)
        prog_layout.addWidget(self.status_lbl, stretch=1)
        right_layout.addLayout(prog_layout)

        out_group = QGroupBox("【 实时扫描输出 】")
        out_v = QVBoxLayout(out_group)
        out_v.setContentsMargins(4, 6, 4, 4)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont("Consolas", 10))
        self.output_area.setMinimumHeight(280)
        self.output_area.setStyleSheet(
            "background:#050505;border:1px solid #00ff41;"
            "color:#00ff41;font-family:Consolas,monospace;"
        )
        out_v.addWidget(self.output_area)

        stats_row = QHBoxLayout()
        self.vuln_count_lbl = QLabel("发现问题: 0（不含INFO）")
        self.vuln_count_lbl.setStyleSheet("color:#ff0041;font-weight:bold;")
        stats_row.addWidget(self.vuln_count_lbl)
        stats_row.addStretch()
        out_v.addLayout(stats_row)

        out_group.setLayout(out_v)
        right_layout.addWidget(out_group, stretch=6)

        splitter.addWidget(right_panel)
        splitter.setSizes([260, 860])
        root.addWidget(splitter, stretch=1)

    def _load_config(self):
        self.exe_edit.setText(self.config.get("nuclei_exe", ""))
        self.tmpl_dir_edit.setText(self.config.get("nuclei_template_dir", ""))
        self.out_dir_edit.setText(self.config.get("nuclei_output_dir", "output"))
        tmpl_dir = self.config.get("nuclei_template_dir", "")
        if tmpl_dir:
            self.tmpl_tree.set_template_dir(tmpl_dir)

    def _save_config(self):
        self.config.set("nuclei_exe", self.exe_edit.text().strip())
        self.config.set("nuclei_template_dir", self.tmpl_dir_edit.text().strip())
        self.config.set("nuclei_output_dir", self.out_dir_edit.text().strip())
        self.config.save()
        self._append_output("[配置已保存]", "#00ffff")

    def _browse_exe(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 nuclei 可执行文件", "",
            "可执行文件 (*.exe);;所有文件 (*)"
        )
        if path:
            self.exe_edit.setText(path)

    def _browse_tmpl_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择 nuclei-templates 目录")
        if path:
            self.tmpl_dir_edit.setText(path)

    def _browse_out_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择结果输出目录")
        if path:
            self.out_dir_edit.setText(path)

    def _reload_templates(self):
        tmpl_dir = self.tmpl_dir_edit.text().strip()
        if not tmpl_dir:
            QMessageBox.warning(self, "提示", "请先配置模板目录")
            return
        self.tmpl_load_lbl.setText("加载中...")
        self.tmpl_tree.set_template_dir(tmpl_dir)
        self._append_output("开始加载模板目录: %s" % tmpl_dir, "#00ffff")


    def _on_tmpl_load_progress(self, count: int, dir_name: str):
        self.tmpl_load_lbl.setText("扫描中 %d..." % count)

    def _load_targets_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                self.target_list.setPlainText(content)
                self._append_output("已加载目标文件: %s" % path, "#00ffff")
            except Exception as e:
                QMessageBox.critical(self, "错误", "读取文件失败: %s" % e)

    def _clear_targets(self):
        self.target_list.clear()
        self.target_edit.clear()

    def _on_template_selection(self, paths: list):
        self.selected_count_lbl.setText("已选: %d 个模板" % len(paths))

    def _update_target_count(self):
        lines = [
            l.strip()
            for l in self.target_list.toPlainText().splitlines()
            if l.strip()
        ]
        self.tgt_count_lbl.setText("%d 个目标" % len(lines))

    def add_targets(self, targets: List[str]):
        """从外部（如 FOFA 模块）追加目标"""
        existing = self.target_list.toPlainText().strip()
        new_lines = "\n".join(targets)
        if existing:
            self.target_list.setPlainText(existing + "\n" + new_lines)
        else:
            self.target_list.setPlainText(new_lines)
        self._append_output(
            "已从 FOFA 导入 %d 个目标" % len(targets), "#00ffff"
        )
        self.request_switch_tab.emit()

    def start_scan(self):
        nuclei_exe = self.exe_edit.text().strip()
        if not nuclei_exe:
            QMessageBox.warning(self, "配置缺失", "请先配置 nuclei 可执行文件路径")
            return
        if not Path(nuclei_exe).exists():
            QMessageBox.warning(
                self, "文件不存在",
                "找不到 nuclei 可执行文件:\n%s" % nuclei_exe
            )
            return

        targets = []
        single = self.target_edit.text().strip()
        if single:
            targets.append(single)
        list_text = self.target_list.toPlainText().strip()
        if list_text:
            for line in list_text.splitlines():
                line = line.strip()
                if line and line not in targets:
                    targets.append(line)

        if not targets:
            QMessageBox.warning(self, "无目标", "请输入至少一个扫描目标")
            return

        templates = self.tmpl_tree.get_checked_templates()
        if not templates:
            reply = QMessageBox.question(
                self, "未选模板",
                "未勾选任何模板，将使用 nuclei 默认模板扫描，是否继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        extra = self._build_extra_args()

        out_file = ""
        out_dir = self.out_dir_edit.text().strip()
        if out_dir:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = str(Path(out_dir) / ("nuclei_%s.jsonl" % ts))

        self.output_area.clear()
        self._vuln_count = 0
        self.vuln_count_lbl.setText("发现问题: 0（不含INFO）")
        self._scan_start_time = datetime.now()
        self._timer.start(1000)

        self.progress_bar.setMaximum(0)
        self.progress_bar.setFormat("扫描中...")
        self.status_lbl.setText("扫描中...")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self._append_output(
            "[ 开始扫描 ] 目标: %d 个  模板: %d 个  时间: %s"
            % (len(targets), len(templates), datetime.now().strftime("%H:%M:%S")),
            "#00ffff"
        )

        simple = self.simple_mode_cb.isChecked()
        self.runner = NucleiRunner(nuclei_exe, targets, templates, extra, out_file,
                                   simple_mode=simple)
        self.runner.output_signal.connect(self._append_output)
        self.runner.output_rich_signal.connect(self._append_rich_output)
        self.runner.progress_signal.connect(self._on_progress)
        self.runner.finished_signal.connect(self._on_finished)
        self.runner.start()

    def _build_extra_args(self) -> List[str]:
        extra = []

        for flag, btn in self._quick_btns.items():
            if btn.isChecked():
                extra.append(flag)

        proxy = self.proxy_combo.currentText().strip()
        if proxy:
            extra += ["-proxy", proxy]

        extra_raw = self.extra_args_edit.text().strip()
        if extra_raw:
            import shlex
            try:
                extra += shlex.split(extra_raw)
            except Exception:
                extra += extra_raw.split()

        return extra

    def stop_scan(self):
        if self.runner:
            self.runner.stop()
            self.status_lbl.setText("正在停止...")

    def _on_progress(self, count: int, msg: str):
        self._vuln_count = count
        self.vuln_count_lbl.setText("发现问题: %d（不含INFO）" % count)
        self.status_lbl.setText(msg)

    def _on_finished(self, ok: bool, msg: str):
        self._timer.stop()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(100 if ok else 0)
        self.progress_bar.setFormat("完成" if ok else "失败")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        color = "#00ffff" if ok else "#ff0041"
        self._append_output("[ %s ] %s" % ("完成" if ok else "失败", msg), color)
        self.status_lbl.setText("完成" if ok else "失败")

    def _tick_timer(self):
        if self._scan_start_time:
            elapsed = datetime.now() - self._scan_start_time
            s = int(elapsed.total_seconds())
            self.elapsed_lbl.setText("%02d:%02d" % (s // 60, s % 60))

    def _append_output(self, line: str, color: str = "#00ff41"):
        """单色行追加（CMD提示/日志/漏洞格式化行）"""
        ts = datetime.now().strftime("%H:%M:%S")
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText("[%s] %s\n" % (ts, line))
        self.output_area.setTextCursor(cursor)
        self.output_area.ensureCursorVisible()

    def _append_rich_output(self, segments: list):
        """
        多色段追加（来自 ANSI 解析）。
        segments: [(text, color_hex_or_None), ...]
        """
        ts = datetime.now().strftime("%H:%M:%S")
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        fmt = cursor.charFormat()
        fmt.setForeground(QColor("#555555"))
        cursor.setCharFormat(fmt)
        cursor.insertText("[%s] " % ts)

        for text, color in segments:
            fmt = cursor.charFormat()
            fmt.setForeground(QColor(color if color else "#00ff41"))
            cursor.setCharFormat(fmt)
            cursor.insertText(text)

        fmt = cursor.charFormat()
        fmt.setForeground(QColor("#00ff41"))
        cursor.setCharFormat(fmt)
        cursor.insertText("\n")

        self.output_area.setTextCursor(cursor)
        self.output_area.ensureCursorVisible()

        doc = self.output_area.document()
        if doc.blockCount() > 8000:
            trim_cursor = self.output_area.textCursor()
            trim_cursor.movePosition(QTextCursor.MoveOperation.Start)
            trim_cursor.movePosition(
                QTextCursor.MoveOperation.Down,
                QTextCursor.MoveMode.KeepAnchor, 500
            )
            trim_cursor.removeSelectedText()

    def _clear_output(self):
        self.output_area.clear()
        self._vuln_count = 0
        self.vuln_count_lbl.setText("发现问题: 0（不含INFO）")
        self.elapsed_lbl.setText("00:00")
        self.status_lbl.setText("就绪")
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("就绪")

    def _export_results(self):
        text = self.output_area.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "提示", "输出区域为空")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存扫描输出", "output/nuclei_output.txt",
            "文本文件 (*.txt);;JSONL文件 (*.jsonl)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                QMessageBox.information(self, "成功", "已保存到:\n%s" % path)
            except Exception as e:
                QMessageBox.critical(self, "保存失败", str(e))

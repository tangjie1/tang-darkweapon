"""
Nuclei 执行器  v1.5
使用 QThread + subprocess 实时读取 nuclei 进程输出
新增：
  - ANSI 转义码解析（保留 nuclei 原始颜色）
  - 支持"最简命令"模式（仅 -u/-t/-jsonl/-o，不附加任何额外参数）
  - v1.5: 统计排除 INFO 级别，只统计真实安全问题
"""
import re
import json as _json
import subprocess
from typing import List, Optional

from PyQt6.QtCore import QThread, pyqtSignal


# ──────────────────────────────────────────────────────────
#  ANSI 颜色解析器
# ──────────────────────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")

_ANSI_COLOR_MAP = {
    "0":  None,
    "1":  None,
    "30": "#333333",
    "31": "#ff4444",
    "32": "#00cc44",
    "33": "#ffcc00",
    "34": "#4488ff",
    "35": "#ff44cc",
    "36": "#00cccc",
    "37": "#aaaaaa",
    "90": "#555555",
    "91": "#ff0041",
    "92": "#00ff41",
    "93": "#ffaa00",
    "94": "#00aaff",
    "95": "#cc44ff",
    "96": "#00ffcc",
    "97": "#ffffff",
}

_DEFAULT_COLOR = "#00ff41"


def parse_ansi(line: str) -> List[tuple]:
    """
    解析带 ANSI 转义码的文本行，返回 [(text_segment, color_hex), ...]。
    color_hex 为 None 表示使用默认颜色。
    """
    segments = []
    pos = 0
    current_color = None

    for m in _ANSI_RE.finditer(line):
        if m.start() > pos:
            seg = line[pos:m.start()]
            if seg:
                segments.append((seg, current_color))

        codes = m.group(1).split(";")
        for code in codes:
            if code == "0" or code == "":
                current_color = None
            elif code in _ANSI_COLOR_MAP:
                c = _ANSI_COLOR_MAP[code]
                if c is not None:
                    current_color = c
        pos = m.end()

    if pos < len(line):
        seg = line[pos:]
        if seg:
            segments.append((seg, current_color))

    segments = [(t, c) for t, c in segments if t.strip() or t == " "]
    if not segments:
        clean = _ANSI_RE.sub("", line)
        segments = [(clean, None)]
    return segments


def strip_ansi(line: str) -> str:
    """去除 ANSI 转义码，返回纯文本"""
    return _ANSI_RE.sub("", line)


# ──────────────────────────────────────────────────────────
#  NucleiRunner
# ──────────────────────────────────────────────────────────
class NucleiRunner(QThread):
    """
    在后台线程中运行 nuclei，实时转发输出到 GUI。

    信号:
        output_signal(str, str)          - (行文本, 颜色代码)  ← 普通单色行
        output_rich_signal(list)         - [(text, color), ...]  ← 多色段（ANSI）
        progress_signal(int, str)        - (漏洞数, 状态描述)
        finished_signal(bool, str)       - (是否成功, 结束消息)
    """

    output_signal      = pyqtSignal(str, str)
    output_rich_signal = pyqtSignal(list)
    progress_signal    = pyqtSignal(int, str)
    finished_signal    = pyqtSignal(bool, str)

    SEVERITY_COLORS = {
        "critical": "#ff0041",
        "high":     "#ff6600",
        "medium":   "#ffaa00",
        "low":      "#00aaff",
        "info":     "#00ff41",
        "unknown":  "#888888",
    }

    def __init__(
        self,
        nuclei_exe: str,
        targets: List[str],
        templates: List[str],
        extra_args: List[str],
        output_file: str = "",
        simple_mode: bool = False,
    ):
        super().__init__()
        self.nuclei_exe  = nuclei_exe
        self.targets     = targets
        self.templates   = templates
        self.extra_args  = extra_args
        self.output_file = output_file
        self.simple_mode = simple_mode
        self._process: Optional[subprocess.Popen] = None
        self._stop_flag  = False
        self._done_count = 0
        self._tmp_target_file = None

    def _build_cmd(self) -> List[str]:
        cmd = [self.nuclei_exe]

        if len(self.targets) == 1 and self.targets[0].endswith(".txt"):
            cmd += ["-l", self.targets[0]]
        elif len(self.targets) == 1:
            cmd += ["-u", self.targets[0]]
        else:
            import tempfile, os
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8"
            )
            tmp.write("\n".join(self.targets))
            tmp.close()
            self._tmp_target_file = tmp.name
            cmd += ["-l", tmp.name]

        for t in self.templates:
            cmd += ["-t", t]

        cmd += ["-jsonl"]

        if self.output_file:
            cmd += ["-o", self.output_file]

        if not self.simple_mode:
            cmd += self.extra_args

        return cmd

    def run(self):
        self._done_count = 0
        self._tmp_target_file = None

        try:
            cmd = self._build_cmd()
            self.output_signal.emit("[ CMD ] " + " ".join(cmd), "#555555")

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

            for raw_line in self._process.stdout:
                if self._stop_flag:
                    break
                line = raw_line.rstrip()
                if not line:
                    continue

                self._handle_line(line)

            self._process.wait()
            ret = self._process.returncode

        except FileNotFoundError:
            self.finished_signal.emit(
                False,
                "找不到 nuclei 可执行文件，请在设置中配置正确路径：\n%s" % self.nuclei_exe,
            )
            return
        except Exception as e:
            self.finished_signal.emit(False, "运行出错: %s" % str(e))
            return
        finally:
            if self._tmp_target_file:
                try:
                    import os
                    os.unlink(self._tmp_target_file)
                except Exception:
                    pass

        if self._stop_flag:
            self.finished_signal.emit(False, "扫描已手动停止")
        elif ret == 0:
            self.finished_signal.emit(True, "扫描完成，共发现问题 %d 个（不含INFO级别）" % self._done_count)
        else:
            self.finished_signal.emit(
                False, "nuclei 退出码 %d，请检查命令行参数" % ret
            )

    def _handle_line(self, line: str):
        clean = strip_ansi(line)

        # ① JSONL 漏洞行
        if clean.startswith("{"):
            try:
                obj = _json.loads(clean)
                sev      = obj.get("info", {}).get("severity", "info").lower()
                color    = self.SEVERITY_COLORS.get(sev, _DEFAULT_COLOR)
                template = obj.get("template-id", obj.get("templateID", ""))
                host     = obj.get("host", obj.get("matched-at", ""))
                name     = obj.get("info", {}).get("name", "")
                matcher  = obj.get("matcher-name", "")
                display  = "[%s] [%s] %s  ➜  %s" % (
                    sev.upper().center(8), template, name, host
                )
                if matcher:
                    display += "  [%s]" % matcher

                # 只统计真实漏洞（排除 info/informational）
                if sev not in ("info", "informational", "unknown"):
                    self._done_count += 1
                    self.progress_signal.emit(self._done_count, "发现问题: %d 个" % self._done_count)

                self.output_signal.emit(display, color)
                return
            except Exception:
                pass

        # ② ANSI 行
        if "\x1b[" in line:
            segments = parse_ansi(line)
            self.output_rich_signal.emit(segments)
            return

        # ③ 普通文本行
        color = _DEFAULT_COLOR
        if "[ERR]" in clean or "[FTL]" in clean:
            color = "#ff0041"
        elif "[WRN]" in clean:
            color = "#ffaa00"
        elif "[INF]" in clean:
            color = "#555555"
        self.output_signal.emit(clean, color)

    def stop(self):
        self._stop_flag = True
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
            except Exception:
                pass

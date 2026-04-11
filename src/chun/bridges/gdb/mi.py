"""GDB/MI bridge。"""

from __future__ import annotations

import subprocess
from typing import Any, Callable, TextIO

from ...core.errors import DebuggerBridgeError
from ...core.models import ContextKind, GdbMiResult, ObservationKind, RecordDomain, TargetSpec
from ...core.registry import EvidenceRegistry


class _MiParser:
    """最小 GDB/MI 结果解析器。"""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def parse(self) -> object:
        if not self.text:
            return {}
        return self._parse_value()

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _consume(self, count: int = 1) -> str:
        data = self.text[self.pos : self.pos + count]
        self.pos += count
        return data

    def _parse_value(self) -> object:
        token = self._peek()
        if token == "{":
            return self._parse_dict()
        if token == "[":
            return self._parse_list()
        if token == '"':
            return self._parse_string()
        return self._parse_atom()

    def _parse_dict(self) -> dict[str, object]:
        result: dict[str, object] = {}
        self._consume()
        while self._peek() and self._peek() != "}":
            key = str(self._parse_atom())
            if self._peek() == "=":
                self._consume()
            result[key] = self._parse_value()
            if self._peek() == ",":
                self._consume()
        if self._peek() == "}":
            self._consume()
        return result

    def _parse_list(self) -> list[object]:
        result: list[object] = []
        self._consume()
        while self._peek() and self._peek() != "]":
            if self._peek().isalnum():
                start = self.pos
                key = self._parse_atom()
                if self._peek() == "=":
                    self.pos = start
                    result.append(self._parse_assignment())
                else:
                    result.append(key)
            else:
                result.append(self._parse_value())
            if self._peek() == ",":
                self._consume()
        if self._peek() == "]":
            self._consume()
        return result

    def _parse_assignment(self) -> dict[str, object]:
        key = str(self._parse_atom())
        self._consume()
        return {key: self._parse_value()}

    def _parse_string(self) -> str:
        self._consume()
        value: list[str] = []
        while self._peek():
            char = self._consume()
            if char == '"':
                break
            if char == "\\" and self._peek():
                escaped = self._consume()
                mapping = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
                value.append(mapping.get(escaped, escaped))
                continue
            value.append(char)
        return "".join(value)

    def _parse_atom(self) -> object:
        start = self.pos
        while self._peek() and self._peek() not in ",]}=":
            self._consume()
        atom = self.text[start : self.pos]
        return atom.strip()


class GdbMiBridge:
    """偏自动化、结构化结果的 GDB/MI bridge。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        target: TargetSpec,
        *,
        gdb_path: str = "gdb",
        process_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.registry = registry
        self.target = target
        self.gdb_path = gdb_path
        self._process_factory = process_factory or subprocess.Popen
        self._process: Any = None
        self._command_index = 0

    @property
    def is_running(self) -> bool:
        return self._process is not None

    def start(self, extra_args: list[str] | None = None) -> None:
        if self._process is not None:
            return
        argv = [self.gdb_path, "--interpreter=mi2"]
        if self.target.binary:
            argv.append(self.target.binary)
        if extra_args:
            argv.extend(extra_args)
        self._process = self._process_factory(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._drain_until_prompt()
        self.registry.set_context(
            "gdb.mi.running",
            True,
            kind=ContextKind.SESSION,
            domain=RecordDomain.DEBUGGER,
        )

    def close(self) -> None:
        if self._process is None:
            return
        if hasattr(self._process, "terminate"):
            self._process.terminate()
        self._process = None
        self.registry.set_context(
            "gdb.mi.running",
            False,
            kind=ContextKind.SESSION,
            domain=RecordDomain.DEBUGGER,
        )

    def _stdout(self) -> TextIO:
        if self._process is None or getattr(self._process, "stdout", None) is None:
            raise DebuggerBridgeError("GDB/MI 进程尚未启动。")
        return self._process.stdout

    def _stdin(self) -> TextIO:
        if self._process is None or getattr(self._process, "stdin", None) is None:
            raise DebuggerBridgeError("GDB/MI 进程尚未启动。")
        return self._process.stdin

    def _drain_until_prompt(self) -> list[str]:
        lines: list[str] = []
        stdout = self._stdout()
        while True:
            line = stdout.readline()
            if line == "":
                break
            stripped = line.rstrip("\n")
            if stripped == "(gdb)":
                break
            lines.append(stripped)
        return lines

    @staticmethod
    def _parse_payload(text: str) -> object:
        if not text:
            return {}
        parser = _MiParser(text)
        return parser.parse()

    def execute(self, command: str) -> GdbMiResult:
        if self._process is None:
            self.start()
        stdin = self._stdin()
        stdin.write(command + "\n")
        stdin.flush()
        lines = self._drain_until_prompt()

        result_class = "unknown"
        payload: object = {}
        console: list[str] = []
        for line in lines:
            if line.startswith("~"):
                console.append(self._parse_payload(line[1:]))
            elif line.startswith("^"):
                body = line[1:]
                if "," in body:
                    result_class, raw_payload = body.split(",", 1)
                    payload = self._parse_payload("{" + raw_payload + "}")
                else:
                    result_class = body
                    payload = {}

        result = GdbMiResult(
            command=command,
            result_class=result_class,
            payload=payload,
            console=[str(item) for item in console],
            records=lines,
        )
        self._command_index += 1
        self.registry.record_observation(
            f"gdb.mi.command.{self._command_index}",
            {
                "command": command,
                "result_class": result.result_class,
                "payload": result.payload,
                "console": result.console,
            },
            kind=ObservationKind.DEBUGGER_OUTPUT,
            domain=RecordDomain.DEBUGGER,
            source="gdb-mi",
            tags=["gdb-mi", "command"],
        )
        return result

    def snapshot_regs(self) -> object:
        return self.execute("-data-list-register-values x").payload

    def snapshot_maps(self) -> object:
        return self.execute('-interpreter-exec console "info proc mappings"').payload

    def backtrace(self) -> object:
        return self.execute("-stack-list-frames").payload


__all__ = ["GdbMiBridge"]

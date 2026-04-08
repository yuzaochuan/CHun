# 安装

## 建议使用虚拟环境

```bash
python -m venv .venv
source .venv/bin/activate
```

## 升级基础打包工具链

```bash
python -m pip install --upgrade pip setuptools wheel
```

## 本地开发安装

```bash
python -m pip install -e .
```

## 文档本地预览

如果尚未安装 MkDocs，可先安装：

```bash
python -m pip install mkdocs
```

然后运行：

```bash
mkdocs serve
mkdocs build
```

## 常见问题排查

- `ModuleNotFoundError: pwn`：先安装 `pwntools`
- `mkdocs: command not found`：确认虚拟环境已激活，或使用 `python -m mkdocs`
- 本地 ELF 无法启动：检查二进制权限与运行依赖

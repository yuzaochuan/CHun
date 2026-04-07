# 迁移说明：my_tools.py -> CHun/chun

## 已完成

- [x] 命名切换：`zenpwn` -> `chun`
- [x] 包布局切换：`src/chun/` + `core/plugins/utils`
- [x] `pyproject.toml` 作为主配置
- [x] 保留极薄 `setup.py` 兼容壳
- [x] 顶层导出：`Tool / Blind / Reg`
- [x] `my_tools.py` 兼容层导入映射到新包
- [x] 测试迁移到 `chun.*` 导入路径

## 本阶段不实现

- heap 利用链路（仅保留 `plugins/heap.py` 占位）

## 下一步建议

- [ ] 增加 `test_auto_search_libc`（可注入 mock 的 LibcSearcher）
- [ ] 在 `plugins/fmt.py` 落地 `fmt` 专项高阶能力
- [ ] 增加 `chun new` CLI 子命令，直接从模板生成 exploit 脚手架

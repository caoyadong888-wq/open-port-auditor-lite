# Open Port Auditor (lite)

## English

### Purpose

A free slice of the open-port auditor. It reads a Linux `ss` capture and compares each listener with a JSON allow list of protocol, port, and bind scope (`loopback` or `any`). Process names are ignored. Netstat text and `specific` address lists are in the full build. The program reads a file. It does not launch `ss` or any other scan.

Lab addresses in the fixtures are loopback, `0.0.0.0`, or left out of this subset. The sample mailbox named in the policy is `audit@example.com`.

### Deliverables

- `deliverables/audit_ports_lite.py` — ss parser and PASS/WARN report.
- `deliverables/baseline_policy.json` — SSH on loopback only.
- `examples/policies/edge-web.json` — filled edge policy: loopback `22`, public `80` and `443`.
- `examples/fixtures/ss_baseline_pass.txt` — loopback SSH capture.
- `examples/fixtures/ss_edge_pass.txt` — edge capture that passes `edge-web`.
- `examples/fixtures/ss_edge_warn.txt` — wildcard SSH and an unexpected `3306`.
- `examples/run_demo.sh` — replays the pass and warn captures.

### Quick start

```bash
bash examples/run_demo.sh
python3 deliverables/audit_ports_lite.py \
  --capture examples/fixtures/ss_edge_pass.txt \
  --policy examples/policies/edge-web.json
```

Exit `0` is PASS. Exit `1` is WARN. Exit `2` means the file or the policy could not be judged. Python 3.9 or newer, standard library only. No network.

## 中文

### 用途

开放端口审计的免费子集。它读取 Linux `ss` 捕获，按协议、端口和绑定范围（`loopback` 或 `any`）比较。进程名被忽略。netstat 文本和 `specific` 地址列表在完整版里。程序只读文件，不启动 `ss` 或其他扫描。

夹具里的地址是回环或 `0.0.0.0`。策略里的示例邮箱是 `audit@example.com`。

### 交付清单

- `deliverables/audit_ports_lite.py` — ss 解析器和 PASS/WARN 报告。
- `deliverables/baseline_policy.json` — 只允许回环 SSH。
- `examples/policies/edge-web.json` — 填好的边缘策略：回环 `22`，公开的 `80` 和 `443`。
- `examples/fixtures/ss_baseline_pass.txt` — 回环 SSH 捕获。
- `examples/fixtures/ss_edge_pass.txt` — 能通过 `edge-web` 的边缘捕获。
- `examples/fixtures/ss_edge_warn.txt` — 通配 SSH 和意外的 `3306`。
- `examples/run_demo.sh` — 重放通过和告警两次捕获。

### 快速开始

```bash
bash examples/run_demo.sh
python3 deliverables/audit_ports_lite.py \
  --capture examples/fixtures/ss_edge_pass.txt \
  --policy examples/policies/edge-web.json
```

退出码 `0` 是 PASS，`1` 是 WARN，`2` 是文件或策略无法判断。需要 Python 3.9 或更新版本，只要标准库。不需要网络。

Full version: GUMROAD_URL

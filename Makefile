BIN_DIR := $(shell pwd)/bin
DAEMON  := $(BIN_DIR)/agent-monitor-daemon
MONITOR_DIR := $(HOME)/.agent-monitor
LISTEN_ADDR ?= 127.0.0.1:9101
LOG_FILE    ?= /tmp/agent-monitor-daemon.log

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -o $(DAEMON) ./cmd/daemon
	@echo "✓ daemon built → $(DAEMON)"

.PHONY: test
test:
	go test ./internal/... -count=1

.PHONY: run
run: build
	$(DAEMON) --listen $(LISTEN_ADDR)

.PHONY: dev
dev: build
	@echo "==> 前台开发模式 (Ctrl+C 停止)"
	$(DAEMON) --listen $(LISTEN_ADDR)

.PHONY: stop
stop:
	@killall agent-monitor-daemon 2>/dev/null \
		&& echo "✓ daemon stopped" \
		|| echo "○ no running daemon"

.PHONY: clean
clean:
	@$(MAKE) --no-print-directory stop
	@rm -rf $(BIN_DIR)

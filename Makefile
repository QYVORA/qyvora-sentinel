.PHONY: install uninstall test lint format check help doctor

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/share/sentinel
CONFDIR ?= /etc/sentinel
DOCDIR ?= $(PREFIX)/share/doc/sentinel

install:
	@echo "Installing QYVORA Sentinel..."
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(LIBDIR)/lib
	install -d $(DESTDIR)$(LIBDIR)/modules
	install -d $(DESTDIR)$(LIBDIR)/plugins
	install -d $(DESTDIR)$(LIBDIR)/configs
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(LIBDIR)/assets
	install -d $(DESTDIR)$(DOCDIR)
	install -d /var/log/sentinel/reports
	install -d /var/log/sentinel/baselines
	chmod 777 /var/log/sentinel /var/log/sentinel/reports /var/log/sentinel/baselines
	install -m 755 sentinel $(DESTDIR)$(BINDIR)/sentinel
	cp -r lib/* $(DESTDIR)$(LIBDIR)/lib/
	cp -r modules/* $(DESTDIR)$(LIBDIR)/modules/
	cp -r plugins/* $(DESTDIR)$(LIBDIR)/plugins/ 2>/dev/null || true
	cp -r assets/* $(DESTDIR)$(LIBDIR)/assets/ 2>/dev/null || true
	for conf in configs/*.conf; do \
		[ ! -f $(DESTDIR)$(CONFDIR)/$$(basename $$conf) ] && install -m 644 $$conf $(DESTDIR)$(CONFDIR)/ || true; \
	done
	cp -r docs/* $(DESTDIR)$(DOCDIR)/ 2>/dev/null || true
	@echo "Installation complete."
	@echo "Run 'sentinel help' to get started."

uninstall:
	@echo "Uninstalling QYVORA Sentinel..."
	rm -f $(DESTDIR)$(BINDIR)/sentinel
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -rf $(DESTDIR)$(DOCDIR)
	@echo "Uninstall complete. Config files in $(CONFDIR) were preserved."

test:
	@echo "Running unit tests..."
	@failed=0; \
	for t in tests/unit/test_*.sh; do \
		bash $$t || failed=$$((failed + 1)); \
	done; \
	echo ""; \
	echo "Running integration tests..."; \
	for t in tests/integration/test_*.sh; do \
		bash $$t || failed=$$((failed + 1)); \
	done; \
	if [ $$failed -gt 0 ]; then \
		echo "Some tests failed!"; \
		exit 1; \
	fi; \
	echo "All tests passed!"

lint:
	@echo "Running ShellCheck..."
	@find . -name "*.sh" -o -name "sentinel" | xargs shellcheck --severity=warning || true
	@echo "ShellCheck complete."

format:
	@echo "Formatting with shfmt..."
	@find . -name "*.sh" -o -name "sentinel" | xargs shfmt -w -i 4 -bn
	@echo "Formatting complete."

format-check:
	@echo "Checking format with shfmt..."
	@find . -name "*.sh" -o -name "sentinel" | xargs shfmt -d -i 4 -bn
	@echo "Format check complete."

check: lint format-check
	@echo "All checks passed!"

doctor:
	@echo "Checking dependencies..."
	@for cmd in bash grep awk sed find ps cat chmod chown id uname ls file stat; do \
		if command -v $$cmd > /dev/null 2>&1; then \
			echo "  ✔ $$cmd"; \
		else \
			echo "  ✖ $$cmd (MISSING - required)"; \
		fi; \
	done
	@for cmd in docker kubectl systemctl journalctl iptables nftables ufw ss netstat; do \
		if command -v $$cmd > /dev/null 2>&1; then \
			echo "  ✔ $$cmd (optional)"; \
		else \
			echo "  ○ $$cmd (not found - optional)"; \
		fi; \
	done

help:
	@echo "QYVORA Sentinel Build System"
	@echo ""
	@echo "Targets:"
	@echo "  install      Install sentinel to system"
	@echo "  uninstall    Remove sentinel from system"  
	@echo "  test         Run all tests"
	@echo "  lint         Run ShellCheck"
	@echo "  format       Format code with shfmt"
	@echo "  format-check Check formatting"
	@echo "  check        Run lint + format-check"
	@echo "  doctor       Check dependencies"
	@echo "  help         Show this help"

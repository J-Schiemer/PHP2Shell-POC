.PHONY: test selftest verify backtrace clean

test:
	uv run python -m unittest discover -s tests -v

verify:
	uv run php2shell-check verify

backtrace:
	uv run php2shell-check backtrace

selftest:
	uv run php2shell-check selftest

clean:
	rm -rf out/runs .work

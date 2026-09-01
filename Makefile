.DEFAULT_GOAL := help

.PHONY: help prefetch policy-vectors security zero-bill

help prefetch policy-vectors security zero-bill:
	@python3 ci/run_make_target.py "$@"

%:
	@python3 ci/run_make_target.py "$@"

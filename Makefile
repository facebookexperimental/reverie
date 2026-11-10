.PHONY: checkout-all check-skill-discovery check-oss-cargo-twins

check-skill-discovery:
	@./scripts/check-skill-discovery.rs

check-oss-cargo-twins:
	@./scripts/check-oss-cargo-twins.sh --self-test
	@./scripts/check-oss-cargo-twins.sh

# First-party Reverie has no backend submodules. Keep the normal recursive
# checkout entry for generic callers; extension repositories own their inputs.
checkout-all:
	@git submodule update --init --recursive

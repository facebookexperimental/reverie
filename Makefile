.PHONY: checkout-all check-skill-discovery

check-skill-discovery:
	@./scripts/check-skill-discovery.rs

# First-party Reverie has no backend submodules. Keep the normal recursive
# checkout entry for generic callers; extension repositories own their inputs.
checkout-all:
	@git submodule update --init --recursive

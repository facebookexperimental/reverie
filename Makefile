SUBMODULE_PROXY ?= $(shell command -v with-proxy 2>/dev/null)
SUBMODULE_GIT = $(SUBMODULE_PROXY) git

.PHONY: checkout-all checkout-e9patch checkout-optional-submodules checkout-sabre \
	sync-submodule-policy

checkout-e9patch:
	@$(SUBMODULE_GIT) -c submodule.third-party/e9patch.update=checkout \
		submodule update --init --recursive -- third-party/e9patch

checkout-sabre:
	@$(SUBMODULE_GIT) -c submodule.third-party/sabre.update=checkout \
		submodule update --init --recursive -- third-party/sabre

checkout-optional-submodules:
	@$(MAKE) --no-print-directory checkout-e9patch
	@$(MAKE) --no-print-directory checkout-sabre

checkout-all: sync-submodule-policy
	@$(SUBMODULE_GIT) submodule update --init --recursive
	@$(MAKE) --no-print-directory checkout-optional-submodules

# Long-lived checkouts created under the retired `update = none` policy keep that
# value in local `.git/config`, and `git submodule init` never overwrites an
# existing local value. A plain `git submodule update --init --recursive` then
# silently skips those submodules ("Skipping submodule ...") even though
# `.gitmodules` now records `update = checkout`. Copy every update policy from
# `.gitmodules` (the source of truth) into `.git/config` so the standard
# recursive init honors the checkout-by-default policy consistently.
sync-submodule-policy:
	@$(SUBMODULE_GIT) submodule sync --recursive >/dev/null 2>&1 || true
	@git config -f .gitmodules --get-regexp '^submodule\..*\.update$$' | \
		while read -r key value; do git config "$$key" "$$value"; done

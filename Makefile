SUBMODULE_PROXY ?= $(shell command -v with-proxy 2>/dev/null)
SUBMODULE_GIT = $(SUBMODULE_PROXY) git

.PHONY: checkout-all checkout-e9patch checkout-optional-submodules checkout-sabre

checkout-e9patch:
	@$(SUBMODULE_GIT) -c submodule.third-party/e9patch.update=checkout \
		submodule update --init --recursive -- third-party/e9patch

checkout-sabre:
	@$(SUBMODULE_GIT) -c submodule.third-party/sabre.update=checkout \
		submodule update --init --recursive -- third-party/sabre

checkout-optional-submodules:
	@$(MAKE) --no-print-directory checkout-e9patch
	@$(MAKE) --no-print-directory checkout-sabre

checkout-all:
	@$(SUBMODULE_GIT) submodule update --init --recursive
	@$(MAKE) --no-print-directory checkout-optional-submodules

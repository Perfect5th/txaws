PLATFORM = $(shell uname)
ifeq ($(PLATFORM), Darwin)
PYBIN = Python
else
PYBIN = python
endif


version:
	@python -c "from txaws import version;print(version.txaws);"


clean:
	find ./ -name "*~" -exec rm {} \;
	find ./ -name "*.pyc" -exec rm {} \;
	find ./ -name "*.pyo" -exec rm {} \;
	find . -name "*.sw[op]" -exec rm {} \;
	rm -rf _trial_temp/ build/ dist/ MANIFEST *.egg-info


build:
	@python setup.py build
	@python setup.py sdist


check-testcase-names:
	@echo "Checking for (possibly) badly named test cases..."
	@find ./txaws|xargs grep Test|grep class|grep -v 'TestCase('


virtual-dir-setup: VERSION ?= 3
virtual-dir-setup:
	-@test -d .venv-$(VERSION) || virtualenv -p $(PYBIN)$(VERSION) .venv-$(VERSION)
	-@test -e .venv-$(VERSION)/bin/twistd || . .venv-$(VERSION)/bin/activate && pip install twisted
	-@test -e .venv-$(VERSION)/bin/pep8 || . .venv-$(VERSION)/bin/activate && pip install pep8
	-@test -e .venv-$(VERSION)/bin/pyflakes || . .venv-$(VERSION)/bin/activate && pip install pyflakes
	-. .venv-$(VERSION)/bin/activate && pip install lxml
	-. .venv-$(VERSION)/bin/activate && pip install PyOpenSSL
	-. .venv-$(VERSION)/bin/activate && pip install venusian
	-. .venv-$(VERSION)/bin/activate && pip install python-dateutil
	-. .venv-$(VERSION)/bin/activate && pip install pyrsistent
	-. .venv-$(VERSION)/bin/activate && pip install treq
ifeq ($(VERSION), 2.5)
	-. .venv-$(VERSION)/bin/activate && pip install elementtree
	-. .venv-$(VERSION)/bin/activate && pip install simplejson
endif

virtual-dir-rebuild: VERSION ?= 3
virtual-dir-rebuild: virtual-dir-remove virtual-dir-setup
.PHONY: virtual-dir-rebuild

virtual-builds:
	-@test -e "`which $(PYBIN)2.5`" && VERSION=2.5 make virtual-dir-setup || echo "Couldn't find $(PYBIN)2.5"
	-@test -e "`which $(PYBIN)2.6`" && VERSION=2.6 make virtual-dir-setup || echo "Couldn't find $(PYBIN)2.6"
	-@test -e "`which $(PYBIN)2.7`" && VERSION=2.7 make virtual-dir-setup || echo "Couldn't find $(PYBIN)2.7"
	-@test -e "`which $(PYBIN)3.6`" && VERSION=3.6 make virtual-dir-setup || echo "Couldn't find $(PYBIN)3.6"

virtual-trial: VERSION ?= 3
virtual-trial:
	-. .venv-$(VERSION)/bin/activate && python -m twisted.trial txaws


virtual-pep8: VERSION ?= 2.7
virtual-pep8:
	-. .venv-$(VERSION)/bin/activate && pep8 --repeat ./txaws


virtual-pyflakes: VERSION ?= 2.7
virtual-pyflakes:
	-. .venv-$(VERSION)/bin/activate && pyflakes ./txaws


virtual-check: VERSION ?= 2.7
virtual-check:
	-VERSION=$(VERSION) make virtual-trial
	-VERSION=$(VERSION) make virtual-pep8
	-VERSION=$(VERSION) make virtual-pyflakes


virtual-setup-build: VERSION ?= 2.7
virtual-setup-build:
	-@. .venv-$(VERSION)/bin/activate && python setup.py build
	-@. .venv-$(VERSION)/bin/activate && python setup.py sdist


virtual-setup-builds: VERSION ?= 2.7
virtual-setup-builds: virtual-builds
	-@test -e "`which python2.5`" && VERSION=2.5 make virtual-setup-build
	-@test -e "`which python2.6`" && VERSION=2.6 make virtual-setup-build
	-@test -e "`which python2.7`" && VERSION=2.7 make virtual-setup-build


virtual-checks: clean virtual-setup-builds
	-@test -e "`which python2.5`" && VERSION=2.5 make virtual-check
	-@test -e "`which python2.6`" && VERSION=2.6 make virtual-check
	-@test -e "`which python2.7`" && VERSION=2.7 make virtual-check
	make check-testcase-names


virtual-uninstall: VERSION ?= 2.7
virtual-uninstall: PACKAGE ?= ""
virtual-uninstall:
	-. .venv-$(VERSION)/bin/activate && pip uninstall $(PACKAGE)


virtual-uninstalls: PACKAGE ?= ""
virtual-uninstalls:
	-@test -e "`which python2.5`" && VERSION=2.5 PACKAGE=$(PACKAGE) make virtual-uninstall
	-@test -e "`which python2.6`" && VERSION=2.6 PACKAGE=$(PACKAGE) make virtual-uninstall
	-@test -e "`which python2.7`" && VERSION=2.7 PACKAGE=$(PACKAGE) make virtual-uninstall


virtual-dir-remove: VERSION ?= 2.7
virtual-dir-remove:
	rm -rfv .venv-$(VERSION)


clean-virtual-builds: clean
	@VERSION=2.5 make virtual-dir-remove
	@VERSION=2.6 make virtual-dir-remove
	@VERSION=2.7 make virtual-dir-remove


virtual-build-clean: clean-virtual-builds build virtual-builds
.PHONY: virtual-build-clean


check: MOD ?= txaws
check: build
	trial $(MOD)


register:
	python setup.py register


upload: check build
	python setup.py sdist upload --show-response

fix-released:
	./admin/update-bug-status fixcommitted fixreleased

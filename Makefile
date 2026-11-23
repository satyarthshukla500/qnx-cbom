# Targets: check (all tests), fetch-schema (CycloneDX schema for the output test)
PY = python3

check:
	cd tests && PYTHONPATH=../src $(PY) -W error::SyntaxWarning -m unittest test_parsers test_product
	@if [ -d tests/ui/node_modules ]; then node tests/ui/ui_test.js; else echo "ui test skipped: run 'cd tests/ui && npm install && npx playwright install chromium'"; fi

fetch-schema:
	mkdir -p build/schema
	for f in bom-1.6.schema.json spdx.schema.json jsf-0.82.schema.json; do \
	  curl -fsSL -o build/schema/$$f https://raw.githubusercontent.com/CycloneDX/specification/master/schema/$$f; done

.PHONY: check fetch-schema

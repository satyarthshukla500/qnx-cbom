# Checks a CycloneDX file against the official 1.6 JSON schema (test tool only).
# Usage: python3 tests/validate_cbom.py FILE.cdx.json [SCHEMA_DIR]
import json
import sys
from importlib.metadata import version

import jsonschema


def validate(path, schema_dir="build/schema"):
    schema = json.load(open(f"{schema_dir}/bom-1.6.schema.json"))
    store = {}
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.load(open(f"{schema_dir}/{name}"))
        store[doc.get("$id", name)] = doc
        store[name] = doc
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    validator = jsonschema.Draft7Validator(schema, resolver=resolver)
    bom = json.load(open(path))
    problems = [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}" for e in validator.iter_errors(bom)]
    # the schema does not check that references are unique and resolvable, so check them here
    refs = [c["bom-ref"] for c in bom.get("components", []) if "bom-ref" in c] + [bom["metadata"]["component"]["bom-ref"]]
    problems += [f"duplicate bom-ref {r}" for r in sorted({r for r in refs if refs.count(r) > 1})]
    for dep in bom.get("dependencies", []):
        problems += [f"dangling reference {r}" for r in [dep["ref"]] + dep.get("dependsOn", []) if r not in refs]
    return problems


if __name__ == "__main__":
    problems = validate(sys.argv[1], *(sys.argv[2:3]))
    print(f"jsonschema {version("jsonschema")}: {sys.argv[1]}: " + ("VALID against CycloneDX 1.6 schema" if not problems else f"{len(problems)} problems"))
    for line in problems[:20]:
        print("  " + line)
    sys.exit(1 if problems else 0)

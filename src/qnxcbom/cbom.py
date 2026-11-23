# Writes the scan as a CycloneDX 1.6 bill of materials with cryptographic assets.
import hashlib
import json
import posixpath
import uuid

from . import __version__
from .libinfo import SSH_PQ_KEX

PRIMITIVE = {"KexAlgorithms": "key-agree", "HostKeyAlgorithms": "signature", "Ciphers": "block-cipher", "MACs": "mac"}


def _occurrence(path):
    return {"occurrences": [{"location": path}]}


def _prop(name, value):
    return {"name": "qnx-cbom:" + name, "value": str(value)}


def _algorithm_component(name, primitive, quantum_zero, extra=None):
    props = {"primitive": primitive}
    if quantum_zero:
        props["nistQuantumSecurityLevel"] = 0
    props.update(extra or {})
    return {"type": "cryptographic-asset", "bom-ref": "algo:" + name, "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props}}


def _is_classical_kex(name):
    return name not in SSH_PQ_KEX


def _is_classical_signature(name):
    return name.startswith(("ssh-rsa", "rsa-", "ecdsa-", "ssh-ed25519", "ssh-ed448", "sk-")) or name == "ssh-dss"


def _config_assets(model, components):
    """Algorithms named in sshd/ssh settings and one protocol asset per config."""
    for name in ("sshd", "ssh"):
        cfg = model["configs"][name]
        if not cfg or not cfg["settings"]:
            continue
        refs = []
        for setting, entry in sorted(cfg["settings"].items()):
            for alg in entry["items"]:
                ref = "algo:" + alg
                if ref not in {c["bom-ref"] for c in components}:
                    classical = (setting == "KexAlgorithms" and _is_classical_kex(alg)) or \
                                (setting == "HostKeyAlgorithms" and _is_classical_signature(alg))
                    components.append(_algorithm_component(alg, PRIMITIVE[setting], classical))
                refs.append(ref)
        protocol = {"type": "cryptographic-asset", "bom-ref": "proto:" + name, "name": name + " settings",
                    "cryptoProperties": {"assetType": "protocol",
                                         "protocolProperties": {"type": "ssh", "cryptoRefArray": sorted(set(refs))}}}
        if cfg["path"]:
            protocol["evidence"] = _occurrence(cfg["path"])
        components.append(protocol)


def _key_assets(model, components):
    for index, key in enumerate(model["keys"]):
        alg = key["algorithm"] + (f"-{key['size']}" if key["size"] else "") + (f"-{key['curve']}" if key["curve"] else "")
        algo_ref = "algo:" + alg
        if algo_ref not in {c["bom-ref"] for c in components}:
            extra = {"curve": key["curve"]} if key["curve"] else {}
            components.append(_algorithm_component(alg, "signature", not key["quantum_safe"], extra))
        props = {"type": key["kind"], "algorithmRef": algo_ref}
        if key["size"]:
            props["size"] = key["size"]
        if key["kind"] == "certificate":
            cert = {}
            if key["subject"]:
                cert["subjectName"] = "CN=" + key["subject"]
            if key["not_after"]:
                cert["notValidAfter"] = key["not_after"]
            asset = {"assetType": "certificate", "certificateProperties": cert}
        else:
            asset = {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": props}
        components.append({"type": "cryptographic-asset", "bom-ref": f"key:{index}", "name": f"{alg} {key['kind']}",
                           "cryptoProperties": asset, "evidence": _occurrence(key["image_path"])})


def build(model):
    components, dependencies = [], []
    lib_refs = {}
    for lib in model["libs"]:
        ref = "lib:" + lib["id"]
        comp = {"type": "library", "bom-ref": ref, "name": lib["soname"], "evidence": _occurrence(lib["image_path"]),
                "properties": [_prop("pq-capable", str(lib["pq_capable"]).lower())]}
        if lib["version"]:
            comp["version"] = lib["version"]
            if lib["family"] == "openssl":
                comp["purl"] = "pkg:generic/openssl@" + lib["version"]
        components.append(comp)
        lib_refs.setdefault(lib["soname"], []).append(ref)
    known = {c["bom-ref"] for c in components}
    for elf in model["elfs"]:
        if not elf["crypto_libs"]:
            continue
        ref = "lib:" + elf["id"] if "lib:" + elf["id"] in known else "elf:" + elf["id"]
        if ref not in known:
            components.append({"type": "application" if elf["kind"] == "executable" else "library", "bom-ref": ref,
                               "name": posixpath.basename(elf["image_path"]), "evidence": _occurrence(elf["image_path"])})
        needs = sorted({r for n in elf["crypto_libs"] for r in lib_refs.get(n, [])})
        if needs:
            dependencies.append({"ref": ref, "dependsOn": needs})
    _config_assets(model, components)
    _key_assets(model, components)
    findings = [_prop("finding", f"{f['severity']} {f['rule']} {f['subject']}") for f in model["findings"]]
    digest = hashlib.sha256(json.dumps(model, sort_keys=True).encode()).digest()
    image = model["image"]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.UUID(bytes=digest[:16], version=5)), "version": 1,
        "metadata": {"timestamp": model["scan_date"] + "T00:00:00Z",
                     "tools": {"components": [{"type": "application", "name": "qnx-cbom", "version": __version__}]},
                     "component": {"type": "firmware", "bom-ref": "image", "name": image["name"],
                                   "properties": [_prop("arch", image["arch"]), _prop("verdict", model["summary"]["verdict"])]}},
        "components": components, "dependencies": dependencies, "properties": findings,
    }

"""Throwaway probe (branch ci/install-matrix/fa-manifest-probe, never merged):
the manifest ollama installs vs the one a plain client gets from the registry."""
import json, sys
def show(tag, path):
    m = json.load(open(path))
    rows = [("config", m["config"].get("mediaType", ""), m["config"]["digest"], m["config"].get("size"))]
    rows += [("layer", l.get("mediaType", ""), l["digest"], l.get("size")) for l in m.get("layers", [])]
    print("== %s (%d layers)" % (tag, len(m.get("layers", []))))
    for kind, mt, d, s in rows:
        print("  %-6s %-48s %s %s" % (kind, mt.replace("application/vnd.ollama.image.", ""), d[:19], s))
    return {(kind, mt, d) for kind, mt, d, s in rows}
model = sys.argv[1]
inst = show("installed by ollama: " + model, sys.argv[2])
reg = show("registry (plain client): " + model, sys.argv[3])
print("-- only installed: %s" % sorted((m.replace("application/vnd.ollama.image.", ""), d[:19]) for k, m, d in inst - reg))
print("-- only registry:  %s" % sorted((m.replace("application/vnd.ollama.image.", ""), d[:19]) for k, m, d in reg - inst))
w = lambda s: {(m, d) for k, m, d in s if k == "config" or m.endswith((".model", ".projector", ".adapter"))}
print("-- config + weights equal: %s" % (w(inst) == w(reg)))

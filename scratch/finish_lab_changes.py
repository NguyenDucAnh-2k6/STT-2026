"""Apply bounded edits to the lab generator and non-secret local settings."""
import ast
from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "firmware/simulator/attack_traffic_generator.py"
source = path.read_text(encoding="utf-8")
lines = source.splitlines(keepends=True)
remove = set()
for node in ast.walk(ast.parse(source)):
    if isinstance(node, ast.If) and isinstance(node.test, ast.Constant) and node.test.value is False:
        remove.update(range(node.lineno - 1, node.end_lineno))
    if isinstance(node, ast.Try) and any(isinstance(child, ast.Name) and child.id in
                                         {"s_bcast", "s_udp", "s_b"} for child in ast.walk(node)):
        remove.update(range(node.lineno - 1, node.end_lineno))
    if isinstance(node, ast.ExceptHandler) and any(isinstance(child, ast.Name) and child.id == "s_u"
                                                  for child in ast.walk(node)):
        remove.update(range(node.lineno, node.end_lineno))
        lines[node.lineno - 1] += "            pass  # Failed TCP requests are not replaced by mislabeled UDP.\n"
source = "".join(line for index, line in enumerate(lines) if index not in remove)
start = source.index("def detect_target_ip()")
end = source.index("def get_broadcast_ip", start)
source = source[:start] + 'def detect_target_ip() -> str:\n    """Use explicit lab configuration; never infer an attack target."""\n    return configured_target()\n\n\n' + source[end:]
source = "\n".join(line for line in source.split("\n") if not any(item in line for item in
    ("# 2. Nếu có ESP32 IP", "# 3. Phát tán", "# Bắn SYN tới ESP32", "# Đồng thời phát", "bcast_ip = get_broadcast_ip")))
source = source.replace("Burst UDP", "Burst UDP")
ast.parse(source)
path.write_text(source, encoding="utf-8", newline="\n")

env = root / ".env"
text = env.read_text(encoding="utf-8") if env.exists() else ""
# Preserve all other values, especially credentials and existing interface selection.
values = {"LAB_TARGET_IP": "127.0.0.1", "LAB_ALLOWED_TARGETS": "127.0.0.1/32", "LAB_HTTP_PORT": "8088"}
values["LAB_CAPTURE_INTERFACES"] = "8"
existing = {line.split("=", 1)[0].strip() for line in text.splitlines() if "=" in line and not line.lstrip().startswith("#")}
additions = [f'{key}="{value}"' for key, value in values.items() if key not in existing]
if additions:
    env.write_text(text.rstrip("\n") + "\n\n# Explicit local attack lab\n" + "\n".join(additions) + "\n", encoding="utf-8", newline="\n")
print("Generator cleanup and missing LAB_* defaults applied; credentials and capture selection preserved.")

import json, sys

sys.stdout.reconfigure(encoding='utf-8')
log_file = r'C:\Users\Chi Mai\.gemini\antigravity-ide\brain\2328e4ed-77e5-42f6-8764-b4f0b075845f\.system_generated\logs\transcript.jsonl'
with open(log_file, 'r', encoding='utf-8') as f:
    lines = [json.loads(line) for line in f]

for entry in lines:
    t = entry.get('type')
    if t == 'USER_INPUT':
        print(f"=== [USER_INPUT Step {entry.get('step_index')}] ===")
        print(entry.get('content'))
        print()
    elif t == 'PLANNER_RESPONSE' and entry.get('content'):
        print(f"=== [ASSISTANT Step {entry.get('step_index')}] ===")
        print(entry.get('content')[:500] + '...')
        print()

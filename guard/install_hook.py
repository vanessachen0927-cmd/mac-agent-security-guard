import json
import pathlib
import shlex
import sys


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    settings_path = root / '.claude' / 'settings.local.json'
    settings_path.parent.mkdir(exist_ok=True)
    if settings_path.exists():
        settings = json.loads(settings_path.read_text(encoding='utf-8'))
        if not isinstance(settings, dict):
            raise ValueError('Settings must be a JSON object')
    else:
        settings = {}
    command = shlex.quote(sys.executable) + ' ' + shlex.quote(str(root / 'guard' / 'hook.py'))
    hooks = settings.setdefault('hooks', {}).setdefault('PreToolUse', [])
    if not any(isinstance(item, dict) and any(h.get('command') == command for h in item.get('hooks', []) if isinstance(h, dict)) for item in hooks):
        hooks.append({'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': command, 'timeout': 10}]})
    settings_path.write_text(json.dumps(settings, indent=2) + '\n', encoding='utf-8')
    print('Installed project-local Claude Code hook: ' + str(settings_path))
    print('Hook runs only when Claude Code is used inside this repository.')


if __name__ == '__main__':
    main()

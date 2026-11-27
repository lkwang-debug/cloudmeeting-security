"""Create local configuration and output directories without connecting to a server."""
import shutil
from pathlib import Path


def main(root=None):
    root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    target = root / 'configs/scan.local.yaml'
    if target.exists():
        print('Existing local configuration preserved.')
    else:
        shutil.copyfile(root / 'configs/scan.example.yaml', target)
        print('Created configs/scan.local.yaml; fill in your authorized environment.')
    for name in ['reports', 'evidence/tokens', 'state', 'tools_cache']:
        (root / name).mkdir(parents=True, exist_ok=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

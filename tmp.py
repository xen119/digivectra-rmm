from pathlib import Path
lines = Path('Server/server.js').read_text().splitlines()
for idx in range(3300, 3345):
    print(f'{idx+1}: {lines[idx]}')

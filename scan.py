import re

src = open(r"C:\Users\MV Polaco\Downloads\Sistema-de-Gestao-de-Limpeza-WC-\server\handlers.py","r",encoding="utf-8").read()
lines = src.splitlines()
hits = []
for i,l in enumerate(lines,1):
    if (l.lstrip().startswith("f\"") or l.lstrip().startswith("f'")) and "\\" in l:
        hits.append((i,l.strip()))
print("F-string backslash hits:", len(hits))
for h in hits[:20]:
    print(h)

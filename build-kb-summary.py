#!/usr/bin/env python3
"""build-kb-summary.py — produce the SUMMARISED knowledge base the Wizard
popup's dropdown browser shows the user, from the full CWES knowledge base the
Wizard AI is grounded in.

Hybrid pipeline (per theory category; labs/`practice` are skipped):
  1. strip examples programmatically — fenced code, images, console output;
  2. LLM-condense the remaining prose with a local Ollama model into terse
     theory notes (fewer words, every concept kept, no examples), chunking
     large categories by section so each call stays inside the context window.

Structure (phase > module > category) is preserved exactly; only each leaf
`content` is rewritten. The run is resumable — already-summarised categories in
an existing output file are kept and skipped — and the output is saved after
every category so partial progress is never lost.

  MODEL=qwen2.5-coder:7b-instruct-q4_K_M ./build-kb-summary.py
"""
import json
import os
import re
import sys
import time

import ollama as ollama_lib

SRC = os.path.expanduser('~/Documents/Study/CWES/cwes_knowledge_base.json')
DST = os.path.expanduser('~/Documents/Study/CWES/cwes_knowledge_base_summary.json')
MODEL = os.environ.get('MODEL', 'qwen2.5-coder:7b-instruct-q4_K_M')
SKIP_CATEGORIES = {'practice'}
CHUNK_BUDGET = 4500          # max chars of source prose per LLM call

FENCE = re.compile(r'```.*?```', re.S)
IMG = re.compile(r'!\[[^\]]*\]\([^)]*\)')
HTMLIMG = re.compile(r'<img[^>]*>', re.I)
MULTINL = re.compile(r'\n{3,}')
H2 = re.compile(r'(?m)^(?=##\s)')
PREAMBLE = re.compile(r'(?i)^\s*(here (is|are)|sure[,!.]|below is|the following)'
                      r'.*?:\s*\n', re.S)

SYS = (
    "You compress web-security training material into terse THEORY notes. "
    "Rules: keep EVERY concept, definition, mechanism, header/parameter name, "
    "and security implication. Remove all examples, payloads, commands, tool "
    "output and step-by-step walkthroughs. Add nothing new. Use as few words as "
    "possible without losing meaning. Keep the markdown section headings. "
    "Output ONLY the condensed notes — no preamble, no closing remarks."
)


def strip_examples(md):
    md = FENCE.sub('', md)
    md = IMG.sub('', md)
    md = HTMLIMG.sub('', md)
    return MULTINL.sub('\n\n', md).strip()


def sections(md):
    """Split into chunks <= CHUNK_BUDGET, breaking on H2 headings and, when a
    single section is still too big, on blank lines."""
    blocks = [b for b in H2.split(md) if b.strip()]
    out, cur = [], ''
    for b in blocks:
        if len(b) > CHUNK_BUDGET:
            if cur:
                out.append(cur); cur = ''
            para, acc = b.split('\n\n'), ''
            for p in para:
                if len(acc) + len(p) > CHUNK_BUDGET and acc:
                    out.append(acc); acc = ''
                acc += p + '\n\n'
            if acc.strip():
                out.append(acc)
        elif len(cur) + len(b) > CHUNK_BUDGET and cur:
            out.append(cur); cur = b
        else:
            cur += b
    if cur.strip():
        out.append(cur)
    return out or ([md] if md.strip() else [])


def condense(chunk):
    r = ollama_lib.chat(model=MODEL, messages=[
        {'role': 'system', 'content': SYS},
        {'role': 'user', 'content': chunk},
    ], options={'temperature': 0.2, 'num_ctx': 8192, 'num_predict': 1200})
    txt = (r.get('message') or {}).get('content', '').strip()
    return PREAMBLE.sub('', txt).strip()


def summarise(content):
    stripped = strip_examples(content)
    if not stripped:
        return ''
    parts = [condense(c) for c in sections(stripped)]
    return '\n\n'.join(p for p in parts if p).strip()


def main():
    full = json.load(open(SRC, encoding='utf-8'))

    # Resume: keep any category already summarised in a previous run.
    done = {}
    if os.path.exists(DST):
        try:
            prev = json.load(open(DST, encoding='utf-8'))
            for p in prev.get('phases', []):
                for m in p.get('modules', []):
                    for c in m.get('categories', []):
                        if (c.get('content') or '').strip():
                            done[(p.get('phase'), m.get('module'),
                                  c.get('title') or c.get('category'))] = c['content']
        except Exception:
            done = {}

    out = {'metadata': dict(full.get('metadata', {}),
                            variant='summary',
                            note='Condensed theory for the Reconner Wizard '
                                 'dropdown browser; examples removed.'),
           'phases': []}

    total = sum(1 for p in full['phases'] for m in p['modules']
                for c in m['categories'] if c.get('category') not in SKIP_CATEGORIES)
    i = 0
    t0 = time.time()
    for p in full['phases']:
        op = {k: v for k, v in p.items() if k != 'modules'}
        op['modules'] = []
        for m in p['modules']:
            om = {k: v for k, v in m.items() if k != 'categories'}
            om['categories'] = []
            for c in m['categories']:
                if c.get('category') in SKIP_CATEGORIES:
                    continue
                i += 1
                label = c.get('title') or c.get('category')
                key = (p['phase'], m['module'], label)
                oc = {k: v for k, v in c.items() if k != 'content'}
                if key in done:
                    oc['content'] = done[key]
                    print(f'[{i}/{total}] skip (done): {p["phase"]} > '
                          f'{m["module"]} > {label}', flush=True)
                else:
                    print(f'[{i}/{total}] summarising: {p["phase"]} > '
                          f'{m["module"]} > {label} '
                          f'({len(c.get("content","") or "")} chars)...',
                          flush=True)
                    st = time.time()
                    oc['content'] = summarise(c.get('content', '') or '')
                    print(f'          -> {len(oc["content"])} chars '
                          f'in {time.time()-st:.0f}s', flush=True)
                om['categories'].append(oc)
                # Save after every category so progress is durable + resumable.
                op_partial = op  # noqa
                _save(out, full, op, om, oc)
            op['modules'].append(om)
        out['phases'].append(op)
    json.dump(out, open(DST, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    print(f'\nDONE: {total} categories -> {DST} '
          f'in {(time.time()-t0)/60:.1f} min', flush=True)


def _save(out, full, op, om, oc):
    """Write a consistent snapshot of everything summarised so far (the in-progress
    phase/module included) so a crash never loses a finished category."""
    snap = {'metadata': out['metadata'], 'phases': list(out['phases'])}
    # rebuild current phase up to current module/category
    cur_p = {k: v for k, v in op.items() if k != 'modules'}
    cur_p['modules'] = list(op['modules'])
    cur_m = {k: v for k, v in om.items() if k != 'categories'}
    cur_m['categories'] = list(om['categories'])
    cur_p['modules'].append(cur_m)
    snap['phases'].append(cur_p)
    tmp = DST + '.tmp'
    json.dump(snap, open(tmp, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    os.replace(tmp, DST)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\ninterrupted — partial summary saved; rerun to resume.',
              file=sys.stderr)
        sys.exit(130)

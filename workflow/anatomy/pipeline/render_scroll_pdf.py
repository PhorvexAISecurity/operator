#!/usr/bin/env python3
"""Render the scrollable anatomy page to a self-contained PDF.

The page relies on the artifact host to draw its mermaid blocks, so printing it directly would
produce a document with 17 blank slots. This pre-renders each block to SVG with the real mermaid
engine, inlines it, adds print rules, then prints with chromium.

Result: a long PDF you scroll -- lane by lane, every edge short -- instead of one canvas with 88
edges that no eye can track.
"""
import paths
import os, re, html, subprocess, sys, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = str(paths.GENERATED_DIR / 'ANATOMY.html')
OUT  = str(paths.GENERATED_DIR / 'ANATOMY.pdf')
IMG  = 'minlag/mermaid-cli'
DOCKER = ['docker'] if subprocess.run(['docker','info'], capture_output=True).returncode == 0 \
         else ['sudo','-n','docker']

import hashlib
subprocess.run([sys.executable, os.path.join(HERE, 'build_scroll_page.py')],
               check=True, capture_output=True)
SRC_MD5 = hashlib.md5(open(SRC,'rb').read()).hexdigest()

work = tempfile.mkdtemp(prefix='anatomy-pdf-')
os.chmod(work, 0o777)
try:
    with open(os.path.join(work,'puppeteer.json'),'w') as f:
        f.write('{"args":["--no-sandbox","--disable-setuid-sandbox"]}\n')
    page = open(SRC).read()
    # The "whole map at once" section is the 60-node/88-edge canvas. On screen it scrolls
    # sideways and is honest reference; on PAPER it is the exact artifact this document exists
    # to replace -- unreadable, and it broke pagination into a blank page plus a clipped
    # remnant. The lanes carry every node and edge it does, legibly.
    page, _n = re.subn(r'<section id="whole">.*?</section>', '', page, flags=re.S)
    assert _n == 1, 'whole-map section not found; check the page structure before printing'
    page = re.sub(r'<li><a href="#whole">[^<]*</a></li>', '', page)
    blocks = re.findall(r'<pre class="mermaid">\n(.*?)\n</pre>', page, re.S)
    print(f'{len(blocks)} diagrams to render')

    svgs = []
    for i, b in enumerate(blocks):
        src = os.path.join(work, f'd{i:02d}.mmd')
        open(src,'w').write(html.unescape(b))
        subprocess.run(DOCKER + ['run','--rm',
            '-e','PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser',
            '-v',f'{work}:/data', IMG,
            '-i',f'/data/d{i:02d}.mmd','-o',f'/data/d{i:02d}.svg',
            '-p','/data/puppeteer.json'], capture_output=True)
        sp = os.path.join(work, f'd{i:02d}.svg')
        if not os.path.exists(sp):
            raise SystemExit(f'diagram {i} did not render; refusing to emit a PDF with a hole in it')
        svg = open(sp).read()
        svg = svg[svg.index('<svg'):]                      # drop any xml prolog / doctype
        svg = re.sub(r'\s(width|height)="[^"]*"', '', svg, count=2)   # let CSS size it
        svgs.append(svg)

    # splice the rendered SVGs in, in order
    it = iter(svgs)
    page = re.sub(r'<pre class="mermaid">\n.*?\n</pre>',
                  lambda m: '<div class="svgwrap">' + next(it) + '</div>', page, flags=re.S)

    PRINT_CSS = """
<style>
:root{color-scheme:light}
.svgwrap svg{max-width:100%;height:auto;display:block;margin:0 auto}
@page{size:210mm 297mm;margin:13mm}
@page wide{size:297mm 210mm;margin:11mm}
#operations,#interactions{page:wide}
@media print{
  nav.jump{display:none}
  body{background:#fff;font-size:10.5pt}
  .wrap{max-width:none;padding:0}
  header.mast{padding-top:0}
  figure,tr,.entry,.legend div{break-inside:avoid}
  h2,h1{break-after:avoid;break-inside:avoid}   /* the LANE nn eyebrow is a span
                                                   inside h2 and was splitting off */
  figcaption{break-before:avoid}
  section{break-before:auto}
  table{font-size:8.6pt}
  td,th{padding:5px 7px}
  .dgm{padding:8px}
  .tw{overflow:visible!important;border-radius:0}
  table{table-layout:fixed;width:100%}
  th{white-space:normal}
  td,th{overflow-wrap:break-word;word-break:normal;hyphens:none}
  #operations table,#interactions table{table-layout:auto;font-size:7.4pt}
  #operations td,#operations th,#interactions td,#interactions th{padding:3px 5px}
  td.id,td.anch{white-space:normal}
  a{text-decoration:none;color:inherit}
}
</style>"""
    page = page.replace('</style>', '</style>' + PRINT_CSS, 1)
    page = ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            + page + '</body></html>').replace('<title>', '<title>', 1)
    # the artifact skeleton is supplied by the host; for a standalone print we add our own
    page = page.replace('<style>', '</head><body><style>', 1)

    php = os.path.join(work, 'page.html')
    open(php,'w').write(page)
    subprocess.run(DOCKER + ['run','--rm','-v',f'{work}:/data','--entrypoint',
        '/usr/bin/chromium-browser', IMG,
        '--headless','--disable-gpu','--no-sandbox','--disable-setuid-sandbox',
        '--font-render-hinting=none','--virtual-time-budget=20000',
        '--no-pdf-header-footer','--print-to-pdf=/data/out.pdf','/data/page.html'],
        capture_output=True)
    pdf = os.path.join(work,'out.pdf')
    if not os.path.exists(pdf):
        raise SystemExit('chromium produced no PDF')
    shutil.copy(pdf, OUT)
    _raw = open(OUT,'rb').read()
    n = len(re.findall(rb'/Type\s*/Page[^s]', _raw))
    # This regex cannot see pages inside compressed object streams (/ObjStm). It returns 0
    # rather than failing, which is how a real document gets reported as empty.
    assert n > 0, ('page count read 0 — if the PDF uses /ObjStm this counter is blind, '
                   'do not report a page count from it')
    print(f'{OUT}\n  {n} pages · {os.path.getsize(OUT)} bytes · {len(svgs)} diagrams inlined'
          f'\n  built from anatomy_scroll.html md5 {SRC_MD5[:12]}')
finally:
    shutil.rmtree(work, ignore_errors=True)

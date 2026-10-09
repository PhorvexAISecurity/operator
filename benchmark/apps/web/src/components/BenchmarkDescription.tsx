import Markdown from 'react-markdown';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';

// Accept the common LaTeX delimiters as well as $ / $$, leaving code literal.
function normalizeMath(value: string) {
  return value.replace(
    /(^ {0,3}(`{3,}|~{3,})[^\n]*\n[\s\S]*?\n {0,3}\2[^\n]*(?=\n|$))|(`+)([^\n]*?)\3|\\\(([\s\S]*?)\\\)|\\\[([\s\S]*?)\\\]/gm,
    (match, fence, _marker, code, _literal, inline, block) => {
      if (fence || code) return match;
      return inline !== undefined ? `$${inline}$` : `\n\n$$\n${block}\n$$\n\n`;
    },
  );
}

export default function BenchmarkDescription({ text }: { text?: string }) {
  if (!text?.trim()) return null;
  return <div className="benchmark-description" dir="ltr">
    <Markdown
      skipHtml
      remarkPlugins={[remarkMath]}
      rehypePlugins={[[rehypeKatex, { trust: false, strict: 'error', maxExpand: 200, maxSize: 10 }]]}
      components={{
        // Descriptions cannot introduce another page title or load remote assets.
        h1: ({ children }) => <p><strong>{children}</strong></p>,
        h2: ({ children }) => <p><strong>{children}</strong></p>,
        h3: ({ children }) => <p><strong>{children}</strong></p>,
        h4: ({ children }) => <p><strong>{children}</strong></p>,
        h5: ({ children }) => <p><strong>{children}</strong></p>,
        h6: ({ children }) => <p><strong>{children}</strong></p>,
        a: ({ children }) => <span>{children}</span>,
        img: ({ alt }) => <span>{alt}</span>,
      }}
    >{normalizeMath(text)}</Markdown>
  </div>;
}

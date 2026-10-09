'use client';

import { useEffect, useId, useRef, useState } from 'react';
import BenchmarkDescription from './BenchmarkDescription';

const PREVIEW_HEIGHT = 240;

export default function BenchmarkRequestDetails({ description, summary, context }: {
  description: string; summary?: string; context?: string;
}) {
  const previewId = useId();
  const content = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [canExpand, setCanExpand] = useState(false);

  useEffect(() => {
    setExpanded(false);
    const element = content.current;
    if (!element) { setCanExpand(false); return; }
    const measure = () => setCanExpand(element.scrollHeight > PREVIEW_HEIGHT);
    measure();
    // Observe the full content so font loading and width changes update overflow.
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, [description]);

  const hasSummary = Boolean(summary?.trim());
  const note = hasSummary ? summary : context;
  const label = hasSummary ? 'Plan summary' : 'Context and notes';

  return <>
    {description.trim() && <div className="benchmark-request" dir="ltr">
      <div id={previewId} className={`benchmark-request-preview${expanded ? '' : ' collapsed'}`}>
        <div ref={content}><BenchmarkDescription text={description}/></div>
      </div>
      {canExpand && <button type="button" className="text-button benchmark-request-toggle"
        aria-controls={previewId} aria-expanded={expanded} onClick={() => setExpanded(value => !value)}>
        {expanded ? 'Show less' : 'Show full request'}
      </button>}
    </div>}
    <p className="request-version-note">The request text guides the plan summary only. It changes neither code nor policy; this run tested the deployed version and the live policy objective shown here.</p>
    {note?.trim() && <section className="benchmark-summary" aria-label={label} dir="ltr">
      <span className="stat-label">{label}</span><BenchmarkDescription text={note}/>
    </section>}
  </>;
}

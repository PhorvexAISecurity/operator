import { display, type Version } from '@/lib/api';
import { hasRecordedValue, recordedVersionFields } from '@/lib/presentation';

export default function VersionDetails({ version, compact = false }: { version?: Version; compact?: boolean }) {
  const fields = recordedVersionFields(version);
  const recorded = fields.filter(field => hasRecordedValue(field.value));
  const primary = recorded.filter(field => ['operator', 'console', 'source'].includes(field.key));
  const visible = compact ? (primary.length ? primary : recorded) : fields;
  return <span className={`version-details${compact ? ' compact' : ''}`} dir="ltr">
    {visible.length ? visible.map(field => <span className="version-field" key={field.key}>
      <span className="version-field-label">{field.label}: </span><code>{display(field.value)}</code>
    </span>) : <span className="version-field">Not recorded</span>}
  </span>;
}

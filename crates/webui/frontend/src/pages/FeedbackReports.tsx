import { useState } from 'react';
import { ShieldAlert, ShieldCheck, Trash2, X } from 'lucide-react';
import { api, FeedbackOverview } from '../api';
import { Empty, ErrorBanner, formatDate, formatRelative, IconButton, numberFmt, Panel, plural, SkeletonRows, useFeedback, useResource } from '../ui';

/** Complaints from mailbox providers' feedback loops (ARF, RFC 5965). */
export function FeedbackPanel() {
  const { run, confirm } = useFeedback();
  const [account, setAccount] = useState('');
  const overview = useResource(
    () => api<FeedbackOverview>(`/api/feedback?days=30${account ? `&account=${encodeURIComponent(account)}` : ''}`),
    [account],
    60000,
  );
  const data = overview.data;

  async function remove(id: number) {
    if (!await confirm({ title: 'Delete report?', message: <>Delete this feedback report? Complaint counts drop accordingly.</>, confirmLabel: 'Delete', danger: true })) return;
    await run(() => api('/api/feedback', 'DELETE', { id }), 'Deleted feedback report');
    overview.reload();
  }

  const subtitle = data && data.addresses.length === 0
    ? 'No feedback loop addresses are configured. Add the addresses you registered with mailbox providers under Settings → Filtering.'
    : `Abuse reports received at ${data?.addresses.join(', ') || '…'}. An account with ${data?.threshold || 'too many'} authenticated complaints in a day is logged as a warning.`;

  return (
    <>
      <ErrorBanner error={overview.error} />
      <Panel title="Complaints by sender" subtitle={`Last ${data?.days ?? 30} days. Unverified reports failed DMARC and may be forged.`}>
        <div className="metricList">
          {data?.senders.length ? data.senders.map((row) => (
            <div className="metric" key={row.sender || '-'}>
              <span>
                {row.sender
                  ? <button type="button" className="linkButton" onClick={() => setAccount(row.sender)} title="Show this sender's reports">{row.sender}</button>
                  : <em>not a local sender</em>}
              </span>
              <strong>
                {plural(row.complaints, 'complaint')}
                {row.unverified > 0 && <small className="muted"> · {numberFmt.format(row.unverified)} unverified</small>}
              </strong>
            </div>
          )) : <Empty>No complaints.</Empty>}
        </div>
      </Panel>
      <Panel
        title="Feedback reports"
        subtitle={subtitle}
        actions={account ? <button type="button" className="button" onClick={() => setAccount('')} aria-label={`Show all reports, not only ${account}`}><X size={16} />{account}</button> : undefined}
      >
        <div className="tableScroll">
          <table>
            <thead><tr><th>Received</th><th>Type</th><th>Sender</th><th>Reporter</th><th>Original message</th><th><span className="visuallyHidden">Actions</span></th></tr></thead>
            <tbody>
              {data === null && !overview.error && <SkeletonRows cols={6} />}
              {data?.reports.map((report) => (
                <tr key={report.id}>
                  <td className="nowrap" title={formatDate(report.received_at)}>{formatRelative(report.received_at)}</td>
                  <td className="nowrap">
                    <span className={report.feedback_type === 'not-spam' ? 'pill ok' : 'pill warn'}>{report.feedback_type}{report.auth_failure ? `: ${report.auth_failure}` : ''}</span>
                    {report.incidents > 1 && <small className="muted"> ×{numberFmt.format(report.incidents)}</small>}
                  </td>
                  <td title={report.attributed_by ? `Matched by ${report.attributed_by}` : 'Not tied to a local account or domain'}>
                    {report.account || report.domain || <span className="muted">{report.original_mail_from || report.original_from || '—'}</span>}
                  </td>
                  <td>
                    {report.authenticated
                      ? <span className="pill ok" title="The report passed DMARC"><ShieldCheck size={13} />{report.reporter || '—'}</span>
                      : <span className="pill error" title="The report failed DMARC and may be forged"><ShieldAlert size={13} />{report.reporter || 'unverified'}</span>}
                  </td>
                  <td className="muted">
                    <span className="clampText" title={[report.original_subject, report.original_message_id, report.source_ip && `source ${report.source_ip}`, report.arrival_date].filter(Boolean).join('\n')}>
                      {report.original_subject || report.original_message_id || '—'}
                    </span>
                  </td>
                  <td className="rowActions"><IconButton danger label="Delete report" onClick={() => remove(report.id)}><Trash2 size={15} /></IconButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data !== null && data.reports.length === 0 && <Empty>No feedback reports{account ? ` for ${account}` : ''}.</Empty>}
      </Panel>
    </>
  );
}

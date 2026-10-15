import React, { useEffect, useState } from 'react';
import { CalendarCheck, CalendarDays, CalendarX, Check, CircleHelp, MapPin, Repeat, Users, X } from 'lucide-react';
import { Api, Invitation, InvitationAction, InvitationAttendee } from './types';

const statusWords: Record<string, string> = {
  accepted: 'Accepted', declined: 'Declined', tentative: 'Maybe', 'needs-action': 'No answer yet', delegated: 'Delegated',
};

function personName(person: { address: string; name: string } | null): string {
  if (!person) return 'Someone';
  return person.name || person.address;
}

/** "Tue 20 Oct 2026, 09:00–10:00", or the dates of an all-day event. */
function when(invitation: Invitation): string {
  if (invitation.start == null) return '';
  const start = new Date(invitation.start * 1000);
  const end = invitation.end != null ? new Date(invitation.end * 1000) : null;
  const day: Intl.DateTimeFormatOptions = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' };
  const time: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' };
  if (invitation.all_day) {
    // An all-day event ends at the start of the day after its last one.
    const last = end ? new Date(end.getTime() - 1) : start;
    const first = start.toLocaleDateString(undefined, { ...day, timeZone: 'UTC' });
    const final = last.toLocaleDateString(undefined, { ...day, timeZone: 'UTC' });
    return first === final ? `${first}, all day` : `${first} – ${final}`;
  }
  const date = start.toLocaleDateString(undefined, day);
  if (!end) return `${date}, ${start.toLocaleTimeString(undefined, time)}`;
  const sameDay = end.toDateString() === start.toDateString();
  return sameDay
    ? `${date}, ${start.toLocaleTimeString(undefined, time)}–${end.toLocaleTimeString(undefined, time)}`
    : `${date}, ${start.toLocaleTimeString(undefined, time)} – ${end.toLocaleDateString(undefined, day)}, ${end.toLocaleTimeString(undefined, time)}`;
}

function headline(invitation: Invitation): string {
  const organizer = personName(invitation.organizer);
  switch (invitation.method) {
    case 'request':
      return invitation.state === 'not_invited' ? `Invitation from ${organizer}` : `${organizer} invited you`;
    case 'cancel':
      return `${organizer} cancelled this event`;
    case 'reply': {
      const replier = invitation.replier;
      const verb = { accepted: 'accepted', declined: 'declined', tentative: 'tentatively accepted' }[replier?.status ?? ''] ?? 'replied to';
      return `${personName(replier)} ${verb} your invitation`;
    }
  }
}

/** A line under the details saying where things stand. */
function stateNote(invitation: Invitation): string | null {
  switch (invitation.state) {
    case 'outdated': return 'Your calendar has a newer version of this event.';
    case 'cancelled': return 'This event is marked cancelled in your calendar.';
    case 'not_invited': return invitation.method === 'reply'
      ? 'This reply is about an event that is not in your calendar.'
      : 'You are not on the guest list under any of your addresses, so this can’t be answered here.';
    case 'applied': return 'Your calendar shows this answer.';
    case 'not_applied': return 'Your calendar does not show this answer yet: its sender could not be verified, so it was not applied automatically.';
    case 'in_calendar': return invitation.method === 'cancel' ? 'The event is still in your calendar.' : null;
    default: return null;
  }
}

const answers: { action: InvitationAction; label: string; icon: React.ReactNode }[] = [
  { action: 'accepted', label: 'Accept', icon: <Check size={14} /> },
  { action: 'tentative', label: 'Maybe', icon: <CircleHelp size={14} /> },
  { action: 'declined', label: 'Decline', icon: <X size={14} /> },
];

function Guests({ attendees, more }: { attendees: InvitationAttendee[]; more: number }) {
  const [open, setOpen] = useState(false);
  if (attendees.length === 0) return null;
  const counts = attendees.reduce<Record<string, number>>((acc, a) => ({ ...acc, [a.status]: (acc[a.status] ?? 0) + 1 }), {});
  const summary = ['accepted', 'tentative', 'declined', 'needs-action']
    .filter((status) => counts[status])
    .map((status) => `${counts[status]} ${statusWords[status].toLowerCase()}`)
    .join(' · ');
  return (
    <div className="invite-guests">
      <button className="link" onClick={() => setOpen(!open)} aria-expanded={open}>
        <Users size={14} /><span className="invite-count">{attendees.length + more} guest{attendees.length + more === 1 ? '' : 's'}</span>{summary && <span className="muted"> · {summary}</span>}
      </button>
      {open && (
        <ul>
          {attendees.map((attendee) => (
            <li key={attendee.address}>
              <span>{attendee.name || attendee.address}</span>
              <span className={`invite-status ${attendee.status}`}>{statusWords[attendee.status] ?? attendee.status}</span>
            </li>
          ))}
          {more > 0 && <li className="muted">and {more} more</li>}
        </ul>
      )}
    </div>
  );
}

/** The event a message carries, with the answers the user can give. */
export function InvitationCard({ api, folder, uid, invitation: initial }: { api: Api; folder: string; uid: number; invitation: Invitation }) {
  const [invitation, setInvitation] = useState(initial);
  const [busy, setBusy] = useState<InvitationAction | null>(null);
  const [error, setError] = useState('');
  useEffect(() => { setInvitation(initial); setError(''); }, [initial]);

  const act = async (action: InvitationAction) => {
    setBusy(action);
    setError('');
    try {
      const result = await api<{ invitation: Invitation | null }>(
        `/api/folders/${encodeURIComponent(folder)}/messages/${uid}/invitation`,
        { method: 'POST', body: JSON.stringify({ action }) },
      );
      if (result.invitation) setInvitation(result.invitation);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const cancelled = invitation.method === 'cancel';
  const Icon = cancelled ? CalendarX : invitation.method === 'reply' ? CalendarCheck : CalendarDays;
  const note = stateNote(invitation);
  const answerable = invitation.actions.some((action) => action === 'accepted');
  const yourStatus = invitation.your_status && invitation.your_status !== 'needs-action' ? invitation.your_status : null;
  return (
    <section className={`invite-card ${cancelled ? 'cancelled' : ''}`} aria-label="Calendar invitation">
      <div className="invite-icon" aria-hidden="true"><Icon size={20} /></div>
      <div className="invite-body">
        <div className="invite-headline muted small">{headline(invitation)}</div>
        <h2 className="invite-title">{invitation.summary || '(no title)'}</h2>
        {invitation.start != null && <div className="invite-line">{when(invitation)}{invitation.recurring && <span className="muted"> · <Repeat size={12} /> repeats</span>}</div>}
        {invitation.location && <div className="invite-line"><MapPin size={14} />{invitation.location}</div>}
        {invitation.method !== 'reply' && <Guests attendees={invitation.attendees} more={invitation.more_attendees} />}
        {note && <p className="invite-note muted small">{note}</p>}
        {(answerable || yourStatus) && (
          <div className="invite-actions">
            {answerable && <span className="muted small">{yourStatus ? `You answered: ${statusWords[yourStatus] ?? yourStatus}. Change?` : 'Going?'}</span>}
            {!answerable && yourStatus && <span className="muted small">You answered: {statusWords[yourStatus] ?? yourStatus}</span>}
            {answerable && answers.map(({ action, label, icon }) => (
              <button key={action} className={yourStatus === action ? 'primary' : 'secondary'} aria-pressed={yourStatus === action}
                disabled={busy !== null} onClick={() => act(action)}>
                {icon}{busy === action ? 'Sending…' : label}
              </button>
            ))}
          </div>
        )}
        {invitation.actions.includes('cancel') && (
          <div className="invite-actions"><button className="secondary" disabled={busy !== null} onClick={() => act('cancel')}><CalendarX size={14} />{busy ? 'Updating…' : 'Mark cancelled in my calendar'}</button></div>
        )}
        {invitation.actions.includes('apply') && (
          <div className="invite-actions"><button className="secondary" disabled={busy !== null} onClick={() => act('apply')}><CalendarCheck size={14} />{busy ? 'Updating…' : 'Update my calendar'}</button></div>
        )}
        {error && <p className="error small" role="alert">{error}</p>}
      </div>
    </section>
  );
}

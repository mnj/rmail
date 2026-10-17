import React, { useEffect, useState } from 'react';
import { CalendarCheck, CalendarClock, CalendarDays, CalendarX, Check, CircleHelp, MapPin, Repeat, Users, X } from 'lucide-react';
import { Api, Booking, Invitation, InvitationAction, InvitationAttendee, Proposal } from './types';

const statusWords: Record<string, string> = {
  accepted: 'Accepted', declined: 'Declined', tentative: 'Maybe', 'needs-action': 'No answer yet', delegated: 'Delegated',
};

function personName(person: { address: string; name: string } | null): string {
  if (!person) return 'Someone';
  return person.name || person.address;
}

/** "Tue 20 Oct 2026, 09:00–10:00", or the dates of an all-day event. */
function when(startSeconds: number | null, endSeconds: number | null, allDay: boolean): string {
  if (startSeconds == null) return '';
  const start = new Date(startSeconds * 1000);
  const end = endSeconds != null ? new Date(endSeconds * 1000) : null;
  const day: Intl.DateTimeFormatOptions = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' };
  const time: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' };
  if (allDay) {
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
    case 'counter':
      return `${personName(invitation.replier)} proposed a new time`;
    case 'declinecounter':
      return `${organizer} declined the time you proposed`;
  }
}

/** A line under the details saying where things stand. */
function stateNote(invitation: Invitation): string | null {
  switch (invitation.state) {
    case 'outdated': return 'Your calendar has a newer version of this event.';
    case 'cancelled': return 'This event is marked cancelled in your calendar.';
    case 'not_invited': return invitation.method === 'reply' || invitation.method === 'counter'
      ? `This ${invitation.method === 'reply' ? 'reply' : 'proposal'} is about an event you don’t organize from this account.`
      : 'You are not on the guest list under any of your addresses, so this can’t be answered here.';
    case 'applied': return invitation.method === 'counter' ? 'Your calendar has this time now; the guests were sent the update.' : 'Your calendar shows this answer.';
    case 'not_applied': return 'Your calendar does not show this answer yet: its sender could not be verified, so it was not applied automatically.';
    case 'proposal_declined': return 'The event keeps the time it has.';
    case 'in_calendar': return invitation.method === 'cancel' ? 'The event is still in your calendar.' : null;
    default: return null;
  }
}

const answers: { action: InvitationAction; label: string; icon: React.ReactNode }[] = [
  { action: 'accepted', label: 'Accept', icon: <Check size={14} /> },
  { action: 'tentative', label: 'Maybe', icon: <CircleHelp size={14} /> },
  { action: 'declined', label: 'Decline', icon: <X size={14} /> },
];

const pad = (n: number) => String(n).padStart(2, '0');
/** A `datetime-local` (or, all day, a `date`) input's value for an instant. */
function inputValue(seconds: number, allDay: boolean): string {
  const d = new Date(seconds * 1000);
  if (allDay) return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function fromInput(value: string, allDay: boolean): number | null {
  if (!value) return null;
  const ms = allDay ? Date.parse(`${value}T00:00:00Z`) : new Date(value).getTime();
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/** Another time for the event, to send its organizer. */
function ProposeForm({ invitation, busy, onSend, onClose }: {
  invitation: Invitation; busy: boolean; onSend: (proposal: Proposal) => void; onClose: () => void;
}) {
  const allDay = invitation.all_day;
  const start0 = invitation.start ?? Math.floor(Date.now() / 1000);
  const end0 = invitation.end ?? start0 + 3600;
  const [start, setStart] = useState(inputValue(start0, allDay));
  // An all-day event's last day, not the exclusive end, is what people pick.
  const [end, setEnd] = useState(inputValue(allDay ? end0 - 86_400 : end0, allDay));
  const [comment, setComment] = useState('');
  const startSeconds = fromInput(start, allDay);
  const lastSeconds = fromInput(end, allDay);
  const endSeconds = lastSeconds != null && allDay ? lastSeconds + 86_400 : lastSeconds;
  const valid = startSeconds != null && endSeconds != null && endSeconds > startSeconds;
  return (
    <form className="invite-propose" onSubmit={(event) => {
      event.preventDefault();
      if (valid) onSend({ start: startSeconds!, end: endSeconds!, comment: comment.trim() });
    }}>
      <div className="invite-propose-times">
        <label className="field">{allDay ? 'From' : 'Starts'}<input type={allDay ? 'date' : 'datetime-local'} value={start} required onChange={(e) => setStart(e.target.value)} /></label>
        <label className="field">{allDay ? 'To' : 'Ends'}<input type={allDay ? 'date' : 'datetime-local'} value={end} required onChange={(e) => setEnd(e.target.value)} /></label>
      </div>
      <label className="field">Note (optional)<textarea rows={2} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Would this time work instead?" /></label>
      {!valid && start && end && <p className="error small">The end has to be after the start.</p>}
      <div className="invite-actions">
        <button className="primary" type="submit" disabled={busy || !valid}><CalendarClock size={14} />{busy ? 'Sending…' : 'Send proposal'}</button>
        <button className="secondary" type="button" disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </form>
  );
}

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
  const [proposing, setProposing] = useState(false);
  const [sent, setSent] = useState('');
  useEffect(() => { setInvitation(initial); setError(''); setProposing(false); setSent(''); }, [initial]);

  const act = async (action: InvitationAction, proposal?: Proposal) => {
    setBusy(action);
    setError('');
    setSent('');
    try {
      const result = await api<{ invitation: Invitation | null }>(
        `/api/folders/${encodeURIComponent(folder)}/messages/${uid}/invitation`,
        { method: 'POST', body: JSON.stringify(proposal ? { action, proposal } : { action }) },
      );
      if (result.invitation) setInvitation(result.invitation);
      if (action === 'counter') {
        setProposing(false);
        setSent(`Proposal sent to ${personName(invitation.organizer)}.`);
      }
      if (action === 'decline_counter') setSent('Proposal declined; the event keeps its time.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const cancelled = invitation.method === 'cancel';
  const proposal = invitation.method === 'counter';
  const Icon = cancelled || invitation.method === 'declinecounter' ? CalendarX
    : invitation.method === 'reply' ? CalendarCheck : proposal ? CalendarClock : CalendarDays;
  const note = stateNote(invitation);
  const answerable = invitation.actions.some((action) => action === 'accepted');
  const yourStatus = invitation.your_status && invitation.your_status !== 'needs-action' ? invitation.your_status : null;
  return (
    <section className={`invite-card ${cancelled ? 'cancelled' : ''}`} aria-label="Calendar invitation">
      <div className="invite-icon" aria-hidden="true"><Icon size={20} /></div>
      <div className="invite-body">
        <div className="invite-headline muted small">{headline(invitation)}</div>
        <h2 className="invite-title">{invitation.summary || '(no title)'}</h2>
        {proposal && invitation.state !== 'applied' && invitation.current_start != null && (
          <div className="invite-line"><span className="muted">Now:</span><span className="invite-was">{when(invitation.current_start, invitation.current_end, invitation.all_day)}</span></div>
        )}
        {invitation.start != null && (
          <div className="invite-line">
            {proposal && invitation.state !== 'applied' && <span className="muted">Proposed:</span>}
            {when(invitation.start, invitation.end, invitation.all_day)}
            {invitation.recurring && <span className="muted"> · <Repeat size={12} /> repeats</span>}
          </div>
        )}
        {invitation.comment && <blockquote className="invite-comment">{invitation.comment}</blockquote>}
        {invitation.location && <div className="invite-line"><MapPin size={14} />{invitation.location}</div>}
        {(invitation.method === 'request' || invitation.method === 'cancel') && <Guests attendees={invitation.attendees} more={invitation.more_attendees} />}
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
        {invitation.actions.includes('counter') && !proposing && (
          <div className="invite-actions"><button className="link" disabled={busy !== null} onClick={() => setProposing(true)}><CalendarClock size={14} />Propose a new time</button></div>
        )}
        {proposing && <ProposeForm invitation={invitation} busy={busy === 'counter'} onSend={(p) => act('counter', p)} onClose={() => setProposing(false)} />}
        {invitation.actions.includes('accept_counter') && (
          <div className="invite-actions">
            <button className="primary" disabled={busy !== null} onClick={() => act('accept_counter')}><Check size={14} />{busy === 'accept_counter' ? 'Updating…' : 'Accept new time'}</button>
            <button className="secondary" disabled={busy !== null} onClick={() => act('decline_counter')}><X size={14} />{busy === 'decline_counter' ? 'Sending…' : 'Decline'}</button>
          </div>
        )}
        {invitation.actions.includes('cancel') && (
          <div className="invite-actions"><button className="secondary" disabled={busy !== null} onClick={() => act('cancel')}><CalendarX size={14} />{busy ? 'Updating…' : 'Mark cancelled in my calendar'}</button></div>
        )}
        {invitation.actions.includes('apply') && (
          <div className="invite-actions"><button className="secondary" disabled={busy !== null} onClick={() => act('apply')}><CalendarCheck size={14} />{busy ? 'Updating…' : 'Update my calendar'}</button></div>
        )}
        {sent && <p className="invite-note muted small" role="status">{sent}</p>}
        {error && <p className="error small" role="alert">{error}</p>}
      </div>
    </section>
  );
}

/** A booking request for a resource the user approves bookings of. */
export function BookingCard({ api, booking: initial }: { api: Api; booking: Booking }) {
  const [booking, setBooking] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => setBooking(initial), [initial]);
  async function answer(approve: boolean) {
    setBusy(true);
    setError('');
    try {
      const reply = await api<{ booking: Booking }>('/api/bookings/answer', { method: 'POST', body: JSON.stringify({ resource: booking.resource, uid: booking.uid, approve }) });
      setBooking(reply.booking);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const gone = booking.status === 'gone';
  const state = gone ? 'This booking was cancelled or moved elsewhere.'
    : booking.status === 'accepted' ? 'Approved: the organizer has been told.'
      : booking.status === 'declined' ? 'Declined: the organizer has been told.'
        : 'It fits the calendar and is held as tentative until you answer.';
  return (
    <section className={`invite-card ${gone || booking.status === 'declined' ? 'cancelled' : ''}`} aria-label="Booking request">
      <div className="invite-icon" aria-hidden="true"><CalendarClock size={20} /></div>
      <div className="invite-body">
        <div className="invite-headline muted small">{booking.organizer || 'Someone'} would like to book {booking.resource}</div>
        <h2 className="invite-title">{booking.summary || '(no title)'}</h2>
        {!gone && <div className="invite-line">{when(booking.start, booking.end, booking.all_day)}</div>}
        <p className="invite-note muted small">{state}</p>
        {!gone && (
          <div className="invite-actions">
            <button type="button" className="primary small-button" disabled={busy || booking.status === 'accepted'} onClick={() => answer(true)}><Check size={14} />Approve</button>
            <button type="button" className="secondary small-button" disabled={busy || booking.status === 'declined'} onClick={() => answer(false)}><X size={14} />Decline</button>
          </div>
        )}
        {error && <p className="error small">{error}</p>}
      </div>
    </section>
  );
}

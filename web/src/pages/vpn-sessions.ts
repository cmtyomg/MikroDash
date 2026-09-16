import { el, esc, fmtBytes } from '../dom';
import type { Socket } from '../socket';
import { fmtTs } from './reports';

interface Session {
  id: string; publicKey: string; name: string; interface: string; allowedIp: string;
  endpoint: string; startedAt: number; lastSeenAt: number; endedAt: number | null;
  rx: number; tx: number; endReason: string; partial: boolean;
}
interface History {
  sessions: Session[]; peers: { publicKey: string; name: string }[];
  total: number; rx: number; tx: number; observedAt: number | null; retentionDays: number;
}

export function sessionDuration(start: number, end: number): string {
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor(seconds % 86400 / 3600);
  const minutes = Math.floor(seconds % 3600 / 60);
  return (days ? days + 'd ' : '') + (hours || days ? hours + 'h ' : '') + minutes + 'm ' + seconds % 60 + 's';
}

const reasons: Record<string, string> = {
  inactive: 'Inactive', disabled: 'Peer disabled', removed: 'Peer removed',
  'endpoint-changed': 'IP changed', 'counter-reset': 'Counters reset', 'monitoring-gap': 'Monitoring gap',
};

export function sessionRows(rows: Session[], observedAt: number | null, now = Date.now()): string {
  if (!rows.length) return '<tr><td colspan="9" class="text-muted">No observed sessions yet.</td></tr>';
  return rows.map((s) => {
    const fresh = observedAt !== null && now - observedAt <= 90_000;
    const status = s.endedAt !== null ? reasons[s.endReason] || s.endReason : fresh ? 'Active' : 'Monitoring gap';
    return '<tr><td><strong>' + esc(s.name || s.publicKey.slice(0, 16)) + '</strong>' +
      '<div class="text-muted small">' + esc(s.interface) + ' · ' + esc(s.allowedIp) + '</div></td>' +
      '<td class="font-monospace">' + esc(s.endpoint || 'Unknown') + '</td>' +
      '<td>' + esc(fmtTs(s.startedAt)) + '</td>' +
      '<td>' + esc(fmtTs(s.endedAt ?? s.lastSeenAt)) + '</td>' +
      '<td>≈ ' + sessionDuration(s.startedAt, s.endedAt ?? s.lastSeenAt) + '</td>' +
      '<td>' + esc(fmtBytes(s.rx)) + '</td><td>' + esc(fmtBytes(s.tx)) + '</td>' +
      '<td>' + esc(fmtBytes(s.rx + s.tx)) + '</td>' +
      '<td>' + esc(status) + (s.partial ? '<div class="text-muted small" title="Only observed traffic is counted; the start or a boundary was not fully observed.">Partial observation</div>' : '') + '</td></tr>';
  }).join('');
}

export function initVpnSessions(socket: Socket, isVisible: (page: string) => boolean, routerId: () => string): void {
  const select = el<HTMLSelectElement>('vpnSessionPeer');
  const body = el('vpnSessionsBody');
  if (!select || !body) return;
  const previous = el<HTMLButtonElement>('vpnSessionsPrev');
  const next = el<HTMLButtonElement>('vpnSessionsNext');
  let offset = 0;
  let generation = 0;
  let controller: AbortController | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let selectedRouter = '';
  let displayedQuery = '';
  const pageSize = 50;

  const stop = (): void => {
    generation++;
    controller?.abort();
    clearTimeout(timer);
  };
  const load = async (): Promise<void> => {
    stop();
    if (!isVisible('vpn')) return;
    const id = routerId();
    if (id !== selectedRouter) {
      selectedRouter = id; offset = 0;
      select.innerHTML = '<option value="">All peers</option>';
      displayedQuery = '';
    }
    if (!id) return;
    const ticket = generation;
    controller = new AbortController();
    const query = new URLSearchParams({ routerId: id, peer: select.value, limit: String(pageSize), offset: String(offset) });
    if (query.toString() !== displayedQuery) {
      displayedQuery = query.toString();
      body.innerHTML = '<tr><td colspan="9" class="text-muted">Loading session history…</td></tr>';
      for (const name of ['vpnSessionsSummary', 'vpnSessionsStatus', 'vpnSessionsPage']) {
        const node = el(name); if (node) node.textContent = '';
      }
      if (previous) previous.disabled = true;
      if (next) next.disabled = true;
    }
    try {
      const response = await fetch('/api/vpn/wireguard/sessions?' + query, { signal: controller.signal, cache: 'no-store' });
      if (!response.ok) throw new Error(response.status === 403 ? 'Access to VPN history is denied.' : 'Unable to load WireGuard history.');
      const data = await response.json() as History;
      if (ticket !== generation || id !== routerId()) return;
      if (offset > 0 && offset >= data.total) {
        offset = Math.max(0, Math.floor((data.total - 1) / pageSize) * pageSize);
        void load(); return;
      }
      const value = select.value;
      select.innerHTML = '<option value="">All peers</option>' + data.peers.map((p) =>
        '<option value="' + esc(p.publicKey) + '">' + esc(p.name || p.publicKey.slice(0, 16)) + ' · ' + esc(p.publicKey.slice(0, 8)) + '</option>').join('');
      if (value && !data.peers.some((p) => p.publicKey === value)) {
        select.innerHTML += '<option value="' + esc(value) + '">' + esc(value.slice(0, 16)) + '</option>';
      }
      select.value = value;
      body.innerHTML = sessionRows(data.sessions, data.observedAt);
      const summary = el('vpnSessionsSummary');
      if (summary) summary.textContent = data.total + ' sessions · Uploaded: ' + fmtBytes(data.rx) +
        ' · Downloaded: ' + fmtBytes(data.tx) + ' · Total: ' + fmtBytes(data.rx + data.tx);
      const status = el('vpnSessionsStatus');
      if (status) status.textContent = data.observedAt && Date.now() - data.observedAt <= 90_000
        ? 'Last observation: ' + fmtTs(data.observedAt) : 'No recent observations. Check router connectivity and VPN collection settings.';
      const page = el('vpnSessionsPage');
      if (page) page.textContent = data.total ? (offset + 1) + '–' + Math.min(offset + pageSize, data.total) + ' / ' + data.total : '0 sessions';
      if (previous) previous.disabled = offset === 0;
      if (next) next.disabled = offset + pageSize >= data.total;
    } catch (error) {
      if (ticket !== generation || id !== routerId()) return;
      body.innerHTML = '<tr><td colspan="9" class="text-danger">' + esc(error instanceof Error ? error.message : 'Unable to load history.') + '</td></tr>';
      const summary = el('vpnSessionsSummary'); if (summary) summary.textContent = '';
      const status = el('vpnSessionsStatus'); if (status) status.textContent = '';
      if (previous) previous.disabled = true;
      if (next) next.disabled = true;
    } finally {
      if (ticket === generation && isVisible('vpn')) timer = setTimeout(() => { void load(); }, 10_000);
    }
  };
  select.addEventListener('change', () => { offset = 0; void load(); });
  el('vpnSessionsRefresh')?.addEventListener('click', () => { void load(); });
  previous?.addEventListener('click', () => { offset = Math.max(0, offset - pageSize); void load(); });
  next?.addEventListener('click', () => { offset += pageSize; void load(); });
  document.addEventListener('mikrodash:pagechange', () => { if (isVisible('vpn')) void load(); else stop(); });
  document.addEventListener('mikrodash:routerchange', () => { stop(); selectedRouter = ''; void load(); });
  socket.on('router:switched', () => { stop(); selectedRouter = ''; void load(); });
  socket.on('disconnect', stop);
  socket.on('connect', () => { void load(); });
  if (isVisible('vpn')) void load();
}

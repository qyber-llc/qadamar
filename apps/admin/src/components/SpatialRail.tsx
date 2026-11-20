import type { OverviewResponse } from '../api/types';
import { buildHref } from '../utils/router';
import { useT } from '../i18n';

/** The Spatial layout's widget column (wide screens with a fine pointer only): the figures that matter, each a link
 *  to the screen that acts on it. Read from the overview the shell already holds; nothing is fetched here. */
export function SpatialRail(props: { readonly overview: OverviewResponse | null }) {
  const t = useT();
  const r = t.overview.rail;
  const ov = props.overview;
  if (!ov) return null;
  const widgets = [
    { title: r.pending, figure: ov.counts.pendingChanges, sub: r.pendingSub, href: buildHref('approvals') },
    { title: r.breakGlass, figure: ov.counts.activeBreakGlass, sub: r.breakGlassSub(ov.counts.breakGlassToReview), href: buildHref('break-glass') },
    { title: r.audit, figure: ov.audit.length, sub: ov.audit.verified ? r.auditVerified : r.auditBroken, href: buildHref('audit') },
  ];
  return (
    <aside className="sp-rail" aria-label={r.label}>
      {widgets.map((w) => (
        <a key={w.title} className="sp-card" href={w.href}>
          <span className="sp-card-head"><span className="sp-card-title">{w.title}</span></span>
          <span className="sp-figure"><strong>{w.figure}</strong><span>{w.sub}</span></span>
        </a>
      ))}
    </aside>
  );
}

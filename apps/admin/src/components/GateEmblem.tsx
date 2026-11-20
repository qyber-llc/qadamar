import { GateMark } from './v24/Boot';

/** Decorative product signature; the sign-in heading provides the accessible name. */
export function GateEmblem(props: { readonly name: string }) {
  return (
    <div className="gate-emblem" aria-hidden="true">
      <GateMark size={180} />
      <p className="gate-emblem-name" data-logotype="">{props.name}</p>
      <p style={{ color: 'inherit', fontSize: '14px', letterSpacing: '0.06em' }}>by Qyber LLC</p>
    </div>
  );
}

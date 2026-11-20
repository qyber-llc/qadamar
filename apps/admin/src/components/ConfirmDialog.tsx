import { createPortal } from 'react-dom';
import { useT } from '../i18n';
import { FocusTrapModal } from './FocusTrapModal';

/** A destructive action asked twice. Rendered in the shell root, so the sidebar and header go inert behind it. */
export function ConfirmDialog(props: {
  readonly open: boolean;
  readonly title: string;
  readonly body: string;
  readonly confirmLabel: string;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}) {
  const t = useT();
  const dialog = (
    <FocusTrapModal open={props.open} onClose={props.onCancel} titleId="confirm-dialog-title" title={props.title} variant="modal">
      <p style={{ marginTop: 0 }}>{props.body}</p>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', flexWrap: 'wrap' }}>
        <button type="button" className="btn btn-sm" onClick={props.onCancel}>{t.common.cancel}</button>
        <button type="button" className="btn btn-sm btn-danger" onClick={props.onConfirm}>{props.confirmLabel}</button>
      </div>
    </FocusTrapModal>
  );
  const root = props.open && typeof document !== 'undefined' ? document.getElementById('app-shell-root') : null;
  return root ? createPortal(dialog, root) : dialog;
}

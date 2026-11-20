import { useEffect, useRef, type ReactNode } from 'react';
import { useT } from '../i18n';

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), select:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function FocusTrapModal(props: {
  readonly open: boolean;
  readonly onClose?: () => void;
  readonly titleId: string;
  readonly title: string;
  readonly variant?: 'drawer' | 'modal';
  readonly children: ReactNode;
}) {
  const t = useT();
  const backdropRef = useRef<HTMLDivElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(props.onClose);

  useEffect(() => {
    onCloseRef.current = props.onClose;
  }, [props.onClose]);

  useEffect(() => {
    if (!props.open) return;

    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const backdrop = backdropRef.current;
    const inertedElements: {
      readonly el: HTMLElement;
      readonly prevInert: boolean;
      readonly prevAriaHidden: string | null;
    }[] = [];

    const parent = backdrop?.parentElement;
    if (parent) {
      for (const child of Array.from(parent.children)) {
        if (child !== backdrop && child instanceof HTMLElement) {
          inertedElements.push({
            el: child,
            prevInert: child.hasAttribute('inert'),
            prevAriaHidden: child.getAttribute('aria-hidden'),
          });
          child.setAttribute('inert', '');
          child.setAttribute('aria-hidden', 'true');
        }
      }
    }

    const panel = panelRef.current;
    if (panel) {
      const focusables = panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
      if (focusables[0]) {
        focusables[0].focus();
      } else {
        panel.focus();
      }
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCloseRef.current?.();
        return;
      }
      if (e.key === 'Tab' && panelRef.current) {
        const nodes = Array.from(panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
        if (nodes.length === 0) {
          e.preventDefault();
          return;
        }
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        const active = document.activeElement;
        if (e.shiftKey) {
          if (active === first || !panelRef.current.contains(active)) {
            e.preventDefault();
            last?.focus();
          }
        } else {
          if (active === last || !panelRef.current.contains(active)) {
            e.preventDefault();
            first?.focus();
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      for (const item of inertedElements) {
        if (!item.prevInert) {
          item.el.removeAttribute('inert');
        }
        if (item.prevAriaHidden === null) {
          item.el.removeAttribute('aria-hidden');
        } else {
          item.el.setAttribute('aria-hidden', item.prevAriaHidden);
        }
      }
      if (previousFocusRef.current) {
        previousFocusRef.current.focus();
      }
    };
  }, [props.open]);

  if (!props.open) return null;

  const isModal = props.variant === 'modal';

  return (
    <div
      ref={backdropRef}
      className={isModal ? 'overlay-backdrop modal-center' : 'overlay-backdrop'}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          onCloseRef.current?.();
        }
      }}
    >
      <div
        ref={panelRef}
        className={isModal ? 'modal-panel' : 'drawer-panel'}
        role="dialog"
        aria-modal="true"
        aria-labelledby={props.titleId}
        tabIndex={-1}
      >
        <div className="drawer-header">
          <h2 id={props.titleId} style={{ margin: 0, fontSize: '15px', fontWeight: 700 }}>
            {props.title}
          </h2>
          {props.onClose ? (
            <button type="button" className="btn btn-sm" onClick={() => onCloseRef.current?.()}>
              {t.common.close}
            </button>
          ) : null}
        </div>
        <div className="drawer-body">{props.children}</div>
      </div>
    </div>
  );
}

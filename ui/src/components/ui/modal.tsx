import { PropsWithChildren } from 'react';

interface ModalProps {
  open: boolean;
  title?: string;
  onClose: () => void;
}

export function Modal({ open, title, onClose, children }: PropsWithChildren<ModalProps>): React.JSX.Element | null {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md rounded-md border bg-background p-4 shadow-md">
        {title && <div className="text-base font-medium mb-2">{title}</div>}
        <div>{children}</div>
        <div className="mt-3 text-right">
          <button className="inline-flex items-center rounded-md border px-3 py-1.5 text-sm" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

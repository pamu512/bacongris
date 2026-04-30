import { MaintenanceDashboard } from "./MaintenanceDashboard";

type Props = {
  onDismiss: () => void;
};

/**
 * Full maintenance health table; state is read from `maintenance_status.json` through `MaintenanceManager`.
 */
export function MaintenanceModal({ onDismiss }: Props) {
  return (
    <div
      className="import-backdrop maintenance-modal-backdrop"
      role="presentation"
      onClick={onDismiss}
    >
      <div
        className="import-modal maintenance-modal"
        role="dialog"
        aria-label="CTI project maintenance"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="maintenance-modal-head">
          <h3>CTI project maintenance</h3>
          <button
            type="button"
            className="btn ghost small"
            onClick={onDismiss}
          >
            Close
          </button>
        </div>
        <p className="maintenance-modal-lead">
          Use <strong>Update all datasets (maintenance)</strong> for a one-click refresh of{" "}
          <strong>ASM, CVE, and IOC</strong> (IntelX uses its own schedule or tools). Scheduled runs also
          write <code>maintenance_status.json</code> in the workspace root. CVE data older than 12
          hours is highlighted. The background scheduler runs about every 15 minutes.
        </p>
        <MaintenanceDashboard />
      </div>
    </div>
  );
}

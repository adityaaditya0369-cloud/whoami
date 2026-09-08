import { LearningStatus, STATUS_LABELS } from "@/lib/types";

const STYLES: Record<LearningStatus, string> = {
  NOT_STARTED: "bg-[#EDEBE3] text-[#6B6B63] border-[#DCD9CD]",
  LEARNING: "bg-[#FBF0DE] text-[#8A5A15] border-[#EFD9AE]",
  PRACTICED: "bg-[#E4EDFB] text-[#1E4FB8] border-[#C4D8F5]",
  COMPLETED: "bg-[#E1F1E8] text-[#1F6B45] border-[#BFE2CE]",
};

export default function StatusBadge({ status }: { status: LearningStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-[11px] font-medium ${STYLES[status]}`}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}

const severityStyles: Record<string, string> = {
  CRITICAL: 'bg-red-600/20 text-red-400 border-red-600/40',
  HIGH: 'bg-orange-600/20 text-orange-400 border-orange-600/40',
  MEDIUM: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/40',
  LOW: 'bg-blue-600/20 text-blue-400 border-blue-600/40',
  INFO: 'bg-gray-600/20 text-gray-400 border-gray-600/40',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toUpperCase()
  const style = severityStyles[s] ?? severityStyles.INFO

  return (
    <span className={`${style} text-xs font-semibold px-2 py-0.5 rounded border`}>
      {s}
    </span>
  )
}

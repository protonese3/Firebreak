import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { callTool, parseScanResults, type ScanResult } from '../api'
import GradeCircle from '../components/GradeCircle'
import SeverityBadge from '../components/SeverityBadge'

const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const severityBarColors: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-500',
  INFO: 'bg-gray-500',
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [reportLoading, setReportLoading] = useState(false)
  const [reportText, setReportText] = useState('')
  const [execSummary, setExecSummary] = useState('')
  const [execLoading, setExecLoading] = useState(false)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    callTool('firebreak_results', { scan_id: id })
      .then(text => setResult(parseScanResults(text)))
      .catch(() => setError('Failed to load scan results'))
      .finally(() => setLoading(false))
  }, [id])

  const toggleExpand = (fid: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(fid) ? next.delete(fid) : next.add(fid)
      return next
    })
  }

  const generateReport = async () => {
    setReportLoading(true)
    try {
      const text = await callTool('firebreak_report_generate', { scan_id: id })
      setReportText(text)
    } catch {
      setReportText('Failed to generate report')
    } finally {
      setReportLoading(false)
    }
  }

  const generateExecSummary = async () => {
    setExecLoading(true)
    try {
      const text = await callTool('firebreak_report_executive', { scan_id: id })
      setExecSummary(text)
    } catch {
      setExecSummary('Failed to generate summary')
    } finally {
      setExecLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-500">
        <div className="w-5 h-5 border-2 border-gray-600 border-t-orange-500 rounded-full animate-spin mr-3" />
        Loading results...
      </div>
    )
  }

  if (error || !result) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-400 mb-3">{error || 'No results found'}</p>
          <button onClick={() => navigate('/')} className="text-orange-500 hover:underline text-sm">Back to Dashboard</button>
        </div>
      </div>
    )
  }

  const sorted = [...result.findings].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))
  const counts: Record<string, number> = {}
  for (const f of result.findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1
  }
  const maxCount = Math.max(...Object.values(counts), 1)

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center gap-4">
          <button onClick={() => navigate('/')} className="text-gray-500 hover:text-gray-300 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <div>
            <h1 className="text-lg font-bold">
              <span className="text-orange-500">Fire</span>break
            </h1>
            <p className="text-xs text-gray-500 font-mono">{result.target || `Scan ${id}`}</p>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        <div className="flex flex-col md:flex-row gap-8 mb-10">
          <div className="flex flex-col items-center gap-2">
            <GradeCircle grade={result.grade} />
            <p className="text-sm text-gray-500">Score: {result.score}/100</p>
          </div>

          <div className="flex-1">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Severity Breakdown</h2>
            <div className="space-y-2">
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => {
                const count = counts[sev] ?? 0
                if (count === 0) return null
                return (
                  <div key={sev} className="flex items-center gap-3">
                    <span className="text-xs text-gray-400 w-16 text-right">{sev}</span>
                    <div className="flex-1 bg-gray-800 rounded-full h-5 overflow-hidden">
                      <div
                        className={`${severityBarColors[sev]} h-full rounded-full transition-all duration-500`}
                        style={{ width: `${(count / maxCount) * 100}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 w-6">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        <div className="flex gap-3 mb-8">
          <button
            onClick={generateReport}
            disabled={reportLoading}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {reportLoading ? 'Generating...' : 'Generate Report'}
          </button>
          <button
            onClick={generateExecSummary}
            disabled={execLoading}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {execLoading ? 'Generating...' : 'Executive Summary'}
          </button>
        </div>

        {execSummary && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Executive Summary</h3>
            <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed">{execSummary}</pre>
          </div>
        )}

        {reportText && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Full Report</h3>
            <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed max-h-96 overflow-y-auto">{reportText}</pre>
          </div>
        )}

        <h2 className="text-lg font-semibold mb-4">Findings ({result.findings.length})</h2>
        <div className="space-y-2">
          {sorted.map((finding, i) => (
            <div key={finding.id + i} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <button
                onClick={() => toggleExpand(finding.id + i)}
                className="w-full flex items-center gap-3 p-4 text-left hover:bg-gray-800/50 transition-colors"
              >
                <SeverityBadge severity={finding.severity} />
                <span className="flex-1 text-sm font-medium">{finding.title}</span>
                <Link
                  to={`/findings/${finding.id}`}
                  onClick={e => e.stopPropagation()}
                  className="text-xs text-orange-500 hover:underline mr-2"
                >
                  Details
                </Link>
                <svg
                  className={`w-4 h-4 text-gray-500 transition-transform ${expanded.has(finding.id + i) ? 'rotate-180' : ''}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {expanded.has(finding.id + i) && (
                <div className="px-4 pb-4 border-t border-gray-800">
                  <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono mt-3 leading-relaxed">{finding.description}</pre>
                </div>
              )}
            </div>
          ))}
        </div>

        {sorted.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            <p>No findings parsed from the scan results.</p>
            <details className="mt-4 text-left">
              <summary className="text-sm text-orange-500 cursor-pointer hover:underline">View raw output</summary>
              <pre className="mt-2 text-xs text-gray-500 whitespace-pre-wrap font-mono bg-gray-900 p-4 rounded-xl border border-gray-800 max-h-96 overflow-y-auto">{result.raw}</pre>
            </details>
          </div>
        )}
      </main>
    </div>
  )
}

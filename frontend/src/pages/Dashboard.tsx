import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { callTool, parseScanHistory, type ScanEntry } from '../api'
import GradeCircle from '../components/GradeCircle'
import ScanModal from '../components/ScanModal'

export default function Dashboard() {
  const [scans, setScans] = useState<ScanEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showModal, setShowModal] = useState(false)
  const navigate = useNavigate()

  const loadScans = async () => {
    setLoading(true)
    setError('')
    try {
      const text = await callTool('firebreak_scan_history')
      setScans(parseScanHistory(text))
    } catch {
      setError('Failed to load scan history')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadScans() }, [])

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-5">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              <span className="text-orange-500">Fire</span>break
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">Security Scanner Dashboard</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setShowModal(true)}
              className="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg text-sm font-medium transition-colors"
            >
              New Scan
            </button>
            <button
              onClick={async () => {
                try {
                  const text = await callTool('firebreak_check_code', { path: '.' })
                  alert(text || 'Code check complete')
                } catch {
                  alert('Failed to run code check')
                }
              }}
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition-colors border border-gray-700"
            >
              Check Code
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>

        {loading && (
          <div className="flex items-center gap-3 text-gray-500 py-12 justify-center">
            <div className="w-5 h-5 border-2 border-gray-600 border-t-orange-500 rounded-full animate-spin" />
            Loading scans...
          </div>
        )}

        {error && (
          <div className="text-center py-12">
            <p className="text-red-400 mb-3">{error}</p>
            <button onClick={loadScans} className="text-sm text-orange-500 hover:underline">Retry</button>
          </div>
        )}

        {!loading && !error && scans.length === 0 && (
          <div className="text-center py-16 text-gray-500">
            <p className="text-lg mb-2">No scans yet</p>
            <p className="text-sm">Start your first scan to see results here.</p>
          </div>
        )}

        {!loading && scans.length > 0 && (
          <div className="grid gap-3">
            {scans.map(scan => (
              <button
                key={scan.id}
                onClick={() => navigate(`/scan/${scan.id}`)}
                className="w-full flex items-center gap-5 bg-gray-900 hover:bg-gray-800/80 border border-gray-800 hover:border-gray-700 rounded-xl p-4 transition-all text-left group"
              >
                <GradeCircle grade={scan.grade} size="sm" />
                <div className="flex-1 min-w-0">
                  <p className="font-medium truncate group-hover:text-orange-400 transition-colors">{scan.target}</p>
                  <p className="text-sm text-gray-500 mt-0.5">{scan.date}</p>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-sm font-mono">{scan.score}/100</p>
                  <p className="text-xs text-gray-500">{scan.findings} findings</p>
                </div>
                <svg className="w-5 h-5 text-gray-600 group-hover:text-gray-400 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </button>
            ))}
          </div>
        )}
      </main>

      {showModal && <ScanModal onClose={() => setShowModal(false)} onStarted={loadScans} />}
    </div>
  )
}

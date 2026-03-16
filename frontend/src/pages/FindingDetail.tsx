import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { callTool } from '../api'
import SeverityBadge from '../components/SeverityBadge'

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [detail, setDetail] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [fixText, setFixText] = useState('')
  const [fixLoading, setFixLoading] = useState(false)
  const [verifyText, setVerifyText] = useState('')
  const [verifyLoading, setVerifyLoading] = useState(false)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    callTool('firebreak_finding_detail', { finding_id: id })
      .then(setDetail)
      .catch(() => setError('Failed to load finding'))
      .finally(() => setLoading(false))
  }, [id])

  const getFix = async () => {
    setFixLoading(true)
    try {
      setFixText(await callTool('firebreak_finding_fix', { finding_id: id }))
    } catch {
      setFixText('Failed to get fix suggestion')
    } finally {
      setFixLoading(false)
    }
  }

  const verifyFix = async () => {
    setVerifyLoading(true)
    try {
      setVerifyText(await callTool('firebreak_replay', { finding_id: id }))
    } catch {
      setVerifyText('Failed to verify fix')
    } finally {
      setVerifyLoading(false)
    }
  }

  const sevMatch = detail.match(/\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b/i)
  const titleMatch = detail.match(/#+\s*(.+?)[\n\r]/)

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-500">
        <div className="w-5 h-5 border-2 border-gray-600 border-t-orange-500 rounded-full animate-spin mr-3" />
        Loading finding...
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-400 mb-3">{error}</p>
          <button onClick={() => navigate(-1)} className="text-orange-500 hover:underline text-sm">Go back</button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center gap-4">
          <button onClick={() => navigate(-1)} className="text-gray-500 hover:text-gray-300 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-bold">
              <span className="text-orange-500">Fire</span>break
            </h1>
            {sevMatch && <SeverityBadge severity={sevMatch[1]} />}
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8">
        {titleMatch && (
          <h2 className="text-xl font-bold mb-6">{titleMatch[1].replace(/[*#]/g, '').trim()}</h2>
        )}

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Evidence</h3>
          <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed">{detail}</pre>
        </div>

        <div className="flex gap-3 mb-6">
          <button
            onClick={getFix}
            disabled={fixLoading}
            className="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {fixLoading ? 'Getting Fix...' : 'Get Fix'}
          </button>
          <button
            onClick={verifyFix}
            disabled={verifyLoading}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {verifyLoading ? 'Verifying...' : 'Verify Fix'}
          </button>
        </div>

        {fixText && (
          <div className="bg-gray-900 border border-green-900/50 rounded-xl p-5 mb-4">
            <h3 className="text-sm font-semibold text-green-400 uppercase tracking-wider mb-3">Fix Suggestion</h3>
            <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed">{fixText}</pre>
          </div>
        )}

        {verifyText && (
          <div className="bg-gray-900 border border-blue-900/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-blue-400 uppercase tracking-wider mb-3">Verification Result</h3>
            <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed">{verifyText}</pre>
          </div>
        )}
      </main>
    </div>
  )
}

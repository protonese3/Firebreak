import { useState } from 'react'
import { callTool } from '../api'

const scanTypes = ['full', 'quick', 'passive'] as const

export default function ScanModal({ onClose, onStarted }: { onClose: () => void; onStarted: () => void }) {
  const [url, setUrl] = useState('')
  const [scanType, setScanType] = useState<string>('full')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const startScan = async () => {
    if (!url.trim()) {
      setError('Enter a URL')
      return
    }
    setLoading(true)
    setError('')
    try {
      await callTool('firebreak_scan', { url: url.trim(), scan_type: scanType })
      onStarted()
      onClose()
    } catch {
      setError('Failed to start scan')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-xl font-bold mb-4">New Scan</h2>

        <label className="block text-sm text-gray-400 mb-1">Target URL</label>
        <input
          type="url"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 mb-4 text-gray-100 placeholder-gray-500 focus:outline-none focus:border-orange-500"
          autoFocus
          onKeyDown={e => e.key === 'Enter' && startScan()}
        />

        <label className="block text-sm text-gray-400 mb-1">Scan Type</label>
        <div className="flex gap-2 mb-6">
          {scanTypes.map(t => (
            <button
              key={t}
              onClick={() => setScanType(t)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                scanType === t
                  ? 'bg-orange-500 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>

        {error && <p className="text-red-400 text-sm mb-3">{error}</p>}

        <div className="flex gap-3 justify-end">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors">
            Cancel
          </button>
          <button
            onClick={startScan}
            disabled={loading}
            className="px-5 py-2 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
          >
            {loading ? 'Starting...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </div>
  )
}

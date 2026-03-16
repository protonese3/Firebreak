import { Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import ScanDetail from './pages/ScanDetail'
import FindingDetail from './pages/FindingDetail'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/scan/:id" element={<ScanDetail />} />
      <Route path="/findings/:id" element={<FindingDetail />} />
    </Routes>
  )
}

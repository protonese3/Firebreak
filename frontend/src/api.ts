export async function callTool(name: string, args: Record<string, unknown> = {}): Promise<string> {
  const res = await fetch('/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'tools/call',
      params: { name, arguments: args },
    }),
  })
  const json = await res.json()
  return json.result?.content?.[0]?.text ?? ''
}

export interface ScanEntry {
  id: string
  target: string
  score: number
  grade: string
  findings: number
  date: string
}

export function parseScanHistory(text: string): ScanEntry[] {
  const lines = text.split('\n').filter(l => l.startsWith('|') && !l.includes('---'))
  if (lines.length < 2) return []

  const headers = lines[0].split('|').map(h => h.trim().toLowerCase()).filter(Boolean)
  const idIdx = headers.findIndex(h => h.includes('id') || h.includes('scan'))
  const targetIdx = headers.findIndex(h => h.includes('target') || h.includes('url'))
  const scoreIdx = headers.findIndex(h => h.includes('score'))
  const gradeIdx = headers.findIndex(h => h.includes('grade'))
  const findingsIdx = headers.findIndex(h => h.includes('finding'))
  const dateIdx = headers.findIndex(h => h.includes('date') || h.includes('time'))

  return lines.slice(1).map(line => {
    const cols = line.split('|').map(c => c.trim()).filter(Boolean)
    return {
      id: cols[idIdx] ?? '',
      target: cols[targetIdx] ?? '',
      score: parseInt(cols[scoreIdx] ?? '0', 10),
      grade: cols[gradeIdx] ?? '?',
      findings: parseInt(cols[findingsIdx] ?? '0', 10),
      date: cols[dateIdx] ?? '',
    }
  }).filter(e => e.id)
}

export interface Finding {
  id: string
  severity: string
  title: string
  description: string
}

export interface ScanResult {
  grade: string
  score: number
  target: string
  findings: Finding[]
  raw: string
}

export function parseScanResults(text: string): ScanResult {
  const gradeMatch = text.match(/Grade:\s*([A-F][+-]?)/i)
  const scoreMatch = text.match(/Score:\s*(\d+)/i)
  const targetMatch = text.match(/Target:\s*(\S+)/i)

  const findings: Finding[] = []
  const findingBlocks = text.split(/#{2,3}\s/).filter(Boolean)

  for (const block of findingBlocks) {
    const sevMatch = block.match(/\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b/i)
    const titleMatch = block.match(/^(.+?)[\n\r]/)
    if (sevMatch && titleMatch) {
      findings.push({
        id: `f-${findings.length}`,
        severity: sevMatch[1].toUpperCase(),
        title: titleMatch[1].replace(/[*#]/g, '').trim(),
        description: block.trim(),
      })
    }
  }

  return {
    grade: gradeMatch?.[1] ?? '?',
    score: parseInt(scoreMatch?.[1] ?? '0', 10),
    target: targetMatch?.[1] ?? '',
    findings,
    raw: text,
  }
}

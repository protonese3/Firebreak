const gradeColors: Record<string, string> = {
  A: 'border-green-500 text-green-400',
  B: 'border-yellow-500 text-yellow-400',
  C: 'border-orange-500 text-orange-400',
  D: 'border-red-500 text-red-400',
  F: 'border-red-600 text-red-500',
}

export default function GradeCircle({ grade, size = 'lg' }: { grade: string; size?: 'sm' | 'lg' }) {
  const letter = grade.charAt(0).toUpperCase()
  const color = gradeColors[letter] ?? 'border-gray-500 text-gray-400'
  const dims = size === 'lg' ? 'w-28 h-28 text-5xl border-4' : 'w-12 h-12 text-xl border-2'

  return (
    <div className={`${dims} ${color} rounded-full flex items-center justify-center font-bold`}>
      {grade}
    </div>
  )
}

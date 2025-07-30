interface TerminalOutputProps {
  output: string[]
  isRunning?: boolean
}

export default function TerminalOutput({ output, isRunning = false }: TerminalOutputProps) {
  return (
    <div className="bg-black border border-gray-600 rounded-lg p-4 font-mono text-sm">
      <div className="flex items-center mb-2">
        <div className="flex space-x-2">
          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
          <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
        </div>
        <span className="ml-2 text-gray-400">Terminal</span>
      </div>
      <div className="bg-gray-900 p-3 rounded text-green-400 max-h-64 overflow-y-auto">
        {output.map((line, index) => (
          <div key={index} className="mb-1">
            <span className="text-gray-500">$ </span>
            <span>{line}</span>
          </div>
        ))}
        {isRunning && (
          <div className="flex items-center">
            <span className="text-gray-500">$ </span>
            <span className="text-green-400">Scanning...</span>
            <span className="ml-2 animate-pulse">█</span>
          </div>
        )}
      </div>
    </div>
  )
} 
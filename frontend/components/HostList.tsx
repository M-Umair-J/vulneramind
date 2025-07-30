interface Host {
  ip: string
  hostname?: string
  status: 'online' | 'offline'
  ports: number[]
  services: string[]
}

interface HostListProps {
  hosts: Host[]
  onHostSelect?: (host: Host) => void
}

export default function HostList({ hosts, onHostSelect }: HostListProps) {
  return (
    <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10">
      <h3 className="text-xl font-bold mb-4 text-blue-300">Discovered Hosts</h3>
      <div className="space-y-3">
        {hosts.map((host, index) => (
          <div 
            key={index}
            className="bg-white bg-opacity-5 rounded-lg p-4 border border-white border-opacity-10 hover:bg-opacity-10 transition-all duration-200 cursor-pointer"
            onClick={() => onHostSelect?.(host)}
          >
            <div className="flex justify-between items-center mb-2">
              <div className="flex items-center space-x-3">
                <span className="font-mono text-lg">{host.ip}</span>
                {host.hostname && (
                  <span className="text-gray-400 text-sm">({host.hostname})</span>
                )}
              </div>
              <span className={`px-2 py-1 rounded text-xs ${
                host.status === 'online' ? 'bg-green-500 text-white' : 'bg-red-500 text-white'
              }`}>
                {host.status}
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="text-sm text-gray-400">Ports: {host.ports.join(', ')}</span>
              {host.services.length > 0 && (
                <span className="text-sm text-gray-400">Services: {host.services.join(', ')}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
} 
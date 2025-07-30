import Link from 'next/link'

export default function Header() {
  return (
    <header className="bg-black bg-opacity-50 backdrop-blur-sm border-b border-white border-opacity-10">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link href="/" className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
          Vulneramind
        </Link>
        <nav className="flex space-x-6">
          <Link href="/" className="text-gray-300 hover:text-white transition-colors duration-200">
            Home
          </Link>
          <Link href="/app" className="text-gray-300 hover:text-white transition-colors duration-200">
            Scanner
          </Link>
        </nav>
      </div>
    </header>
  )
} 
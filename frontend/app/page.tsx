import Link from 'next/link'

export default function Home() {
  const features = [
    {
      icon: "🔍",
      title: "Lightning Fast Scanning",
      description: "Scan 1000+ ports in seconds with aggressive, optimized algorithms"
    },
    {
      icon: "🤖",
      title: "AI-Powered Analysis", 
      description: "Smart filtering and exploit prioritization with ML integration"
    },
    {
      icon: "⚡",
      title: "Automated Exploitation",
      description: "One-click exploit execution with payload wizard and shell management"
    },
    {
      icon: "📊",
      title: "Professional Reporting",
      description: "Generate comprehensive pentest reports with remediation strategies"
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <h1 className="text-6xl md:text-8xl font-bold mb-6 bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
            Vulneramind
          </h1>
          <p className="text-xl md:text-2xl text-gray-300 mb-8 max-w-3xl mx-auto">
            AI-Enhanced Network Vulnerability Analysis & Exploitation Suite
          </p>
          
          <Link 
            href="/app"
            className="inline-block bg-gradient-to-r from-blue-500 to-purple-600 hover:from-purple-600 hover:to-blue-500 text-white font-bold py-4 px-8 rounded-full text-lg transition-all duration-300 transform hover:scale-105 shadow-lg"
          >
            Launch Scanner
          </Link>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 mb-16">
          {features.map((feature, index) => (
            <div 
              key={index}
              className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10 hover:bg-opacity-10 transition-all duration-300 group"
            >
              <div className="text-4xl mb-4 group-hover:scale-110 transition-transform duration-300">
                {feature.icon}
              </div>
              <h3 className="text-xl font-bold mb-3 text-blue-300">
                {feature.title}
              </h3>
              <p className="text-gray-300 text-sm leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>

        <footer className="text-center py-8 border-t border-white border-opacity-10">
          <p className="text-gray-400">
            © 2024 Vulneramind. Advanced Network Security Analysis.
          </p>
        </footer>
      </div>
    </div>
  );
} 
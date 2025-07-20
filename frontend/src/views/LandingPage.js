import React from 'react';

const features = [
  {
    icon: (
      <svg className="w-16 h-16 text-white bg-gradient-to-br from-indigo-500 to-purple-700 rounded-full p-4 shadow-lg animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m4 4h-1v-4h-1m-4 4h-1v-4h-1m4 4h-1v-4h-1" /></svg>
    ),
    title: 'Lightning Fast Scanning',
    desc: 'Scan 1000+ ports in seconds with aggressive, optimized algorithms.'
  },
  {
    icon: (
      <svg className="w-16 h-16 text-white bg-gradient-to-br from-pink-500 to-red-500 rounded-full p-4 shadow-lg animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m2 0a2 2 0 100-4 2 2 0 000 4zm-2 0a2 2 0 11-4 0 2 2 0 014 0z" /></svg>
    ),
    title: 'AI-Powered Analysis',
    desc: 'Smart filtering, exploit prioritization, and future ML integration.'
  },
  {
    icon: (
      <svg className="w-16 h-16 text-white bg-gradient-to-br from-green-400 to-blue-600 rounded-full p-4 shadow-lg animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3" /></svg>
    ),
    title: 'Automated Exploitation',
    desc: 'One-click exploit execution with payload wizard and shell management.'
  },
  {
    icon: (
      <svg className="w-16 h-16 text-white bg-gradient-to-br from-yellow-400 to-orange-500 rounded-full p-4 shadow-lg animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 20h9" /></svg>
    ),
    title: 'Beautiful Reporting',
    desc: 'Generate professional, exportable pentest reports with one click.'
  },
];

const LandingPage = () => (
  <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-gray-800 flex flex-col items-center justify-center text-white">
    <header className="w-full text-center py-16">
      <h1 className="text-6xl font-extrabold mb-4 bg-gradient-to-r from-white via-indigo-400 to-purple-600 bg-clip-text text-transparent drop-shadow-lg animate-fade-in">
        Vulneramind
      </h1>
      <p className="text-2xl font-light mb-8 animate-fade-in delay-200">
        AI-Enhanced Network Vulnerability Analysis & Exploitation Suite
      </p>
      <a href="/" className="inline-block px-8 py-3 bg-gradient-to-r from-indigo-500 to-purple-700 rounded-full text-lg font-semibold shadow-lg hover:scale-105 hover:from-purple-700 hover:to-indigo-500 transition-all duration-300">
        Enter Dashboard
      </a>
    </header>
    <section className="flex flex-wrap justify-center gap-12 py-12 animate-fade-in delay-400">
      {features.map((f, i) => (
        <div key={i} className="flex flex-col items-center max-w-xs p-6 bg-white bg-opacity-5 rounded-2xl shadow-xl hover:bg-gradient-to-br hover:from-indigo-700 hover:to-purple-900 transition-all duration-300 group">
          {f.icon}
          <h2 className="text-2xl font-bold mt-6 mb-2 group-hover:text-indigo-300 transition-colors duration-300">{f.title}</h2>
          <p className="text-lg text-gray-200 group-hover:text-white text-center">{f.desc}</p>
        </div>
      ))}
    </section>
    <footer className="mt-auto py-8 text-gray-400 text-sm">
      &copy; {new Date().getFullYear()} Vulneramind. All rights reserved.
    </footer>
    <style>{`
      @keyframes fade-in {
        from { opacity: 0; transform: translateY(40px); }
        to { opacity: 1; transform: none; }
      }
      .animate-fade-in {
        animation: fade-in 1s cubic-bezier(0.4,0,0.2,1) both;
      }
      .delay-200 { animation-delay: 0.2s; }
      .delay-400 { animation-delay: 0.4s; }
    `}</style>
  </div>
);

export default LandingPage; 
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import LandingPage from './views/LandingPage';
import DashboardView from './views/DashboardView';
import TargetView from './views/TargetView';
import ScanView from './views/ScanView';
import ExploitView from './views/ExploitView';
import ReportView from './views/ReportView';

const navLink = 'mx-2 px-4 py-2 rounded-lg text-lg font-semibold transition-all duration-200 hover:bg-gradient-to-r hover:from-indigo-500 hover:to-purple-700 hover:text-white';

const App = () => (
  <Router>
    <nav className="w-full flex justify-center items-center py-4 bg-black bg-opacity-80 shadow-lg sticky top-0 z-50">
      <Link to="/" className={navLink + ' text-white'}>Home</Link>
      <Link to="/dashboard" className={navLink + ' text-white'}>Dashboard</Link>
      <Link to="/targets" className={navLink + ' text-white'}>Targets</Link>
      <Link to="/scan" className={navLink + ' text-white'}>Scan</Link>
      <Link to="/exploits" className={navLink + ' text-white'}>Exploits</Link>
      <Link to="/reports" className={navLink + ' text-white'}>Reports</Link>
    </nav>
    <div className="min-h-screen">
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/dashboard" element={<DashboardView />} />
        <Route path="/targets" element={<TargetView />} />
        <Route path="/scan" element={<ScanView />} />
        <Route path="/exploits" element={<ExploitView />} />
        <Route path="/reports" element={<ReportView />} />
      </Routes>
    </div>
  </Router>
);

export default App; 
import React, { ReactNode, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';

interface LayoutProps {
  children: ReactNode;
}

const Layout = ({ children }: LayoutProps) => {
  const router = useRouter();
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  const isActive = (path: string) => router.pathname === path;

  const menuItems = [
    { path: '/', label: 'Scan', icon: '🎯' },
    { path: '/dashboard', label: 'Dashboard', icon: '📊' },
    { path: '/vulns', label: 'Vulnerabilities', icon: '🛡️' },
    { path: '/attack-surface', label: 'Attack Surface', icon: '🔍' },
    { path: '/best-practices', label: 'Best Practices', icon: '📚' },
    { path: '/settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <div className="min-h-screen bg-gray-100 flex">
      {/* Sidebar */}
      <div className={`bg-gray-900 text-white w-64 space-y-6 py-7 px-2 absolute inset-y-0 left-0 transform ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:relative md:translate-x-0 transition duration-200 ease-in-out`}>
        <div className="flex items-center justify-between px-4">
          <span className="text-2xl font-extrabold">AutoAR</span>
          <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="md:hidden">
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <nav className="flex flex-col space-y-2">
          {menuItems.map((item) => (
            <Link 
              key={item.path} 
              href={item.path}
              className={`flex items-center space-x-3 px-4 py-3 rounded transition duration-200 ${
                isActive(item.path)
                  ? 'bg-blue-600 text-white'
                  : 'hover:bg-gray-800'
              }`}
            >
              <span className="text-xl">{item.icon}</span>
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1">
        {/* Top Navigation */}
        <header className="bg-white shadow-sm">
          <div className="flex items-center justify-between h-16 px-4">
            <button
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="md:hidden text-gray-500 hover:text-gray-700"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Welcome to AutoAR Scanner</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;

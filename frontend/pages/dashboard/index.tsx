import React from 'react';
import Layout from '../../components/Layout';

const DashboardPage = () => {
  // Example data - this would come from your backend
  const stats = {
    totalScans: 24,
    vulnerabilitiesFound: 156,
    criticalVulns: 12,
    highVulns: 34,
    mediumVulns: 58,
    lowVulns: 52,
    domains: 8,
    subdomains: 142
  };

  const recentScans = [
    { domain: 'example.com', date: '2023-12-01', vulnsFound: 23, status: 'Completed' },
    { domain: 'test.org', date: '2023-12-02', vulnsFound: 15, status: 'In Progress' },
    { domain: 'demo.net', date: '2023-12-03', vulnsFound: 8, status: 'Completed' },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-gray-500 text-sm font-medium">Total Scans</h3>
            <p className="text-3xl font-bold text-gray-900">{stats.totalScans}</p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-gray-500 text-sm font-medium">Total Vulnerabilities</h3>
            <p className="text-3xl font-bold text-gray-900">{stats.vulnerabilitiesFound}</p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-gray-500 text-sm font-medium">Domains Scanned</h3>
            <p className="text-3xl font-bold text-gray-900">{stats.domains}</p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-gray-500 text-sm font-medium">Subdomains Found</h3>
            <p className="text-3xl font-bold text-gray-900">{stats.subdomains}</p>
          </div>
        </div>

        {/* Vulnerability Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Vulnerability Distribution</h2>
          <div className="flex space-x-4">
            <div className="flex-1">
              <div className="h-4 bg-gray-200 rounded-full overflow-hidden">
                <div className="h-full bg-red-500" style={{ width: `${(stats.criticalVulns / stats.vulnerabilitiesFound) * 100}%` }}></div>
              </div>
              <p className="text-sm mt-1">Critical: {stats.criticalVulns}</p>
            </div>
            <div className="flex-1">
              <div className="h-4 bg-gray-200 rounded-full overflow-hidden">
                <div className="h-full bg-orange-500" style={{ width: `${(stats.highVulns / stats.vulnerabilitiesFound) * 100}%` }}></div>
              </div>
              <p className="text-sm mt-1">High: {stats.highVulns}</p>
            </div>
            <div className="flex-1">
              <div className="h-4 bg-gray-200 rounded-full overflow-hidden">
                <div className="h-full bg-yellow-500" style={{ width: `${(stats.mediumVulns / stats.vulnerabilitiesFound) * 100}%` }}></div>
              </div>
              <p className="text-sm mt-1">Medium: {stats.mediumVulns}</p>
            </div>
            <div className="flex-1">
              <div className="h-4 bg-gray-200 rounded-full overflow-hidden">
                <div className="h-full bg-blue-500" style={{ width: `${(stats.lowVulns / stats.vulnerabilitiesFound) * 100}%` }}></div>
              </div>
              <p className="text-sm mt-1">Low: {stats.lowVulns}</p>
            </div>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 border-b">
            <h2 className="text-lg font-semibold">Recent Scans</h2>
          </div>
          <div className="divide-y">
            {recentScans.map((scan, index) => (
              <div key={index} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-medium">{scan.domain}</h3>
                    <p className="text-sm text-gray-500">{scan.date}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium">{scan.vulnsFound} vulnerabilities</p>
                    <p className={`text-sm ${
                      scan.status === 'Completed' ? 'text-green-600' : 'text-yellow-600'
                    }`}>
                      {scan.status}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default DashboardPage;

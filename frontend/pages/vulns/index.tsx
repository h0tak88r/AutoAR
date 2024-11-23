import React, { useState } from 'react';
import Layout from '../../components/Layout';

interface Vulnerability {
  id: string;
  domain: string;
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  path: string;
  foundDate: string;
  status: 'Open' | 'Fixed' | 'In Progress';
}

const VulnerabilitiesPage = () => {
  // Example data - this would come from your backend
  const [vulnerabilities] = useState<Vulnerability[]>([
    {
      id: '1',
      domain: 'example.com',
      type: 'SQL Injection',
      severity: 'Critical',
      description: 'SQL injection vulnerability found in login form',
      path: '/login?id=1',
      foundDate: '2023-12-01',
      status: 'Open',
    },
    {
      id: '2',
      domain: 'example.com',
      type: 'XSS',
      severity: 'High',
      description: 'Cross-site scripting vulnerability in comment section',
      path: '/blog/post/1#comments',
      foundDate: '2023-12-02',
      status: 'In Progress',
    },
    // Add more example vulnerabilities here
  ]);

  const [filter, setFilter] = useState({
    severity: 'all',
    status: 'all',
  });

  const getSeverityColor = (severity: string) => {
    const colors = {
      Critical: 'bg-red-100 text-red-800',
      High: 'bg-orange-100 text-orange-800',
      Medium: 'bg-yellow-100 text-yellow-800',
      Low: 'bg-blue-100 text-blue-800',
    };
    return colors[severity as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  const getStatusColor = (status: string) => {
    const colors = {
      Open: 'bg-red-100 text-red-800',
      'In Progress': 'bg-yellow-100 text-yellow-800',
      Fixed: 'bg-green-100 text-green-800',
    };
    return colors[status as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  const filteredVulns = vulnerabilities.filter((vuln) => {
    if (filter.severity !== 'all' && vuln.severity !== filter.severity) return false;
    if (filter.status !== 'all' && vuln.status !== filter.status) return false;
    return true;
  });

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-2xl font-bold">Vulnerabilities</h1>
          <div className="flex space-x-4">
            <select
              className="rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
              value={filter.severity}
              onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <select
              className="rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
              value={filter.status}
              onChange={(e) => setFilter({ ...filter, status: e.target.value })}
            >
              <option value="all">All Statuses</option>
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Fixed">Fixed</option>
            </select>
          </div>
        </div>

        <div className="bg-white shadow overflow-hidden rounded-lg">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Domain/Path
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Severity
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Found Date
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredVulns.map((vuln) => (
                <tr key={vuln.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-gray-900">{vuln.domain}</div>
                    <div className="text-sm text-gray-500">{vuln.path}</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-900">{vuln.type}</div>
                    <div className="text-sm text-gray-500">{vuln.description}</div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getStatusColor(vuln.status)}`}>
                      {vuln.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    {vuln.foundDate}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
};

export default VulnerabilitiesPage;

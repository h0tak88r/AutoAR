import React, { useState } from 'react';
import Layout from '../../components/Layout';

interface Endpoint {
  id: string;
  url: string;
  method: string;
  params: string[];
  headers: Record<string, string>;
  status: number;
  technologies: string[];
}

interface Subdomain {
  hostname: string;
  ip: string;
  ports: number[];
  technologies: string[];
  status: 'active' | 'inactive';
}

const AttackSurfacePage = () => {
  const [activeTab, setActiveTab] = useState<'endpoints' | 'subdomains'>('endpoints');
  
  // Example data - this would come from your backend
  const [endpoints] = useState<Endpoint[]>([
    {
      id: '1',
      url: 'https://api.example.com/users',
      method: 'POST',
      params: ['id', 'name', 'email'],
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer'
      },
      status: 200,
      technologies: ['Node.js', 'Express']
    },
    // Add more endpoints
  ]);

  const [subdomains] = useState<Subdomain[]>([
    {
      hostname: 'api.example.com',
      ip: '192.168.1.1',
      ports: [80, 443, 8080],
      technologies: ['Nginx', 'Node.js'],
      status: 'active'
    },
    // Add more subdomains
  ]);

  return (
    <Layout>
      <div className="space-y-6">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('endpoints')}
              className={`${
                activeTab === 'endpoints'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
            >
              Endpoints
            </button>
            <button
              onClick={() => setActiveTab('subdomains')}
              className={`${
                activeTab === 'subdomains'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm`}
            >
              Subdomains
            </button>
          </nav>
        </div>

        {activeTab === 'endpoints' && (
          <div className="bg-white shadow overflow-hidden rounded-lg">
            <div className="px-4 py-5 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">
                Discovered Endpoints
              </h3>
            </div>
            <div className="border-t border-gray-200">
              <div className="divide-y divide-gray-200">
                {endpoints.map((endpoint) => (
                  <div key={endpoint.id} className="px-4 py-5 sm:px-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          endpoint.method === 'GET' ? 'bg-green-100 text-green-800' :
                          endpoint.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                          endpoint.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-red-100 text-red-800'
                        }`}>
                          {endpoint.method}
                        </span>
                        <span className="ml-2 text-sm font-medium text-gray-900">
                          {endpoint.url}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {endpoint.technologies.map((tech, index) => (
                          <span key={index} className="px-2 py-1 text-xs rounded-md bg-gray-100 text-gray-700">
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="mt-2">
                      <div className="text-sm text-gray-500">
                        <span className="font-medium">Parameters: </span>
                        {endpoint.params.join(', ')}
                      </div>
                      <div className="text-sm text-gray-500">
                        <span className="font-medium">Status: </span>
                        {endpoint.status}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'subdomains' && (
          <div className="bg-white shadow overflow-hidden rounded-lg">
            <div className="px-4 py-5 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">
                Discovered Subdomains
              </h3>
            </div>
            <div className="border-t border-gray-200">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Hostname
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      IP Address
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Open Ports
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Technologies
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {subdomains.map((subdomain, index) => (
                    <tr key={index}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {subdomain.hostname}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {subdomain.ip}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {subdomain.ports.join(', ')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex flex-wrap gap-2">
                          {subdomain.technologies.map((tech, techIndex) => (
                            <span key={techIndex} className="px-2 py-1 text-xs rounded-md bg-gray-100 text-gray-700">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          subdomain.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }`}>
                          {subdomain.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AttackSurfacePage;

import React from 'react';
import Layout from '../../components/Layout';

interface BestPractice {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  recommendation: string;
  references: string[];
}

const BestPracticesPage = () => {
  const bestPractices: BestPractice[] = [
    {
      id: '1',
      title: 'Input Validation',
      description: 'Implement proper input validation to prevent SQL injection, XSS, and other injection attacks.',
      category: 'Security',
      severity: 'Critical',
      recommendation: 'Use parameterized queries, escape special characters, and validate input on both client and server side.',
      references: [
        'https://owasp.org/www-project-top-ten/2021/A03_2021-Injection',
        'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
      ]
    },
    {
      id: '2',
      title: 'Secure Headers',
      description: 'Implement security headers to protect against various attacks.',
      category: 'Security',
      severity: 'High',
      recommendation: 'Add headers like Content-Security-Policy, X-Frame-Options, and X-XSS-Protection.',
      references: [
        'https://owasp.org/www-project-secure-headers/',
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
      ]
    },
    {
      id: '3',
      title: 'Rate Limiting',
      description: 'Implement rate limiting to prevent brute force and DoS attacks.',
      category: 'Security',
      severity: 'High',
      recommendation: 'Use rate limiting middleware and implement exponential backoff.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html'
      ]
    },
    // Add more best practices
  ];

  const categories = Array.from(new Set(bestPractices.map(bp => bp.category)));

  const getSeverityColor = (severity: string) => {
    const colors = {
      Critical: 'bg-red-100 text-red-800',
      High: 'bg-orange-100 text-orange-800',
      Medium: 'bg-yellow-100 text-yellow-800',
      Low: 'bg-blue-100 text-blue-800',
    };
    return colors[severity as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div className="sm:flex sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Security Best Practices</h1>
            <p className="mt-2 text-sm text-gray-700">
              A comprehensive guide to securing your web applications and infrastructure.
            </p>
          </div>
        </div>

        {categories.map(category => (
          <div key={category} className="bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 sm:px-6">
              <h2 className="text-lg leading-6 font-medium text-gray-900">{category}</h2>
            </div>
            <div className="border-t border-gray-200">
              <div className="divide-y divide-gray-200">
                {bestPractices
                  .filter(bp => bp.category === category)
                  .map(practice => (
                    <div key={practice.id} className="px-4 py-5 sm:px-6">
                      <div className="flex items-center justify-between">
                        <h3 className="text-lg font-medium text-gray-900">
                          {practice.title}
                        </h3>
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getSeverityColor(practice.severity)}`}>
                          {practice.severity}
                        </span>
                      </div>
                      <p className="mt-2 text-sm text-gray-500">
                        {practice.description}
                      </p>
                      <div className="mt-4">
                        <h4 className="text-sm font-medium text-gray-900">Recommendation</h4>
                        <p className="mt-2 text-sm text-gray-500">
                          {practice.recommendation}
                        </p>
                      </div>
                      <div className="mt-4">
                        <h4 className="text-sm font-medium text-gray-900">References</h4>
                        <ul className="mt-2 space-y-1">
                          {practice.references.map((ref, index) => (
                            <li key={index}>
                              <a
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sm text-blue-600 hover:text-blue-500"
                              >
                                {ref}
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Layout>
  );
};

export default BestPracticesPage;

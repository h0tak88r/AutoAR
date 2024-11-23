import React, { useState } from 'react'
import Head from 'next/head'
import Layout from '../components/Layout'

interface ScanOptions {
  skip_ports: boolean;
  skip_fuzz: boolean;
  skip_sqli: boolean;
  skip_paramx: boolean;
  verbose: boolean;
  webhook?: string;
}

interface ApiResponse {
  success: boolean;
  output?: string;
  error?: string;
}

export default function Home() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [output, setOutput] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [options, setOptions] = useState<ScanOptions>({
    skip_ports: false,
    skip_fuzz: false,
    skip_sqli: false,
    skip_paramx: false,
    verbose: false,
    webhook: ''
  })

  const startScan = async () => {
    if (!domain) {
      setError('Please enter a domain')
      return
    }

    setLoading(true)
    setError(null)
    setOutput('')

    try {
      // First check if the backend is healthy
      const healthCheck = await fetch('http://localhost:5000/api/health')
      if (!healthCheck.ok) {
        throw new Error('Backend server is not responding')
      }

      const res = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain,
          options
        })
      })

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`)
      }

      const data: ApiResponse = await res.json()
      
      if (data.success) {
        setOutput(data.output || 'Scan completed successfully')
      } else {
        setError(data.error || 'An unknown error occurred')
        setOutput(data.output || '')
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to connect to the server')
    } finally {
      setLoading(false)
    }
  }

  const stopScan = async () => {
    if (!domain) return;
    
    try {
      const res = await fetch(`http://localhost:5000/api/scan/${domain}`, {
        method: 'DELETE'
      });
      
      const data = await res.json();
      if (data.success) {
        setLoading(false);
        setOutput(prev => prev + '\n[!] Scan stopped by user');
      } else {
        setError(data.error || 'Failed to stop scan');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to stop scan');
    }
  };

  return (
    <Layout>
      <div className="max-w-4xl mx-auto">
        <Head>
          <title>AutoAR Scanner</title>
          <meta name="description" content="AutoAR Web Interface" />
          <link rel="icon" href="/favicon.ico" />
        </Head>

        <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
          <h1 className="text-2xl font-bold mb-4">Start New Scan</h1>
          {error && (
            <div className="bg-red-50 border-l-4 border-red-400 p-4 mb-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="domain" className="block text-sm font-medium text-gray-700">
                Target Domain
              </label>
              <input
                type="text"
                id="domain"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              />
            </div>

            <div>
              <label htmlFor="webhook" className="block text-sm font-medium text-gray-700">
                Discord Webhook URL (Optional)
              </label>
              <input
                type="text"
                id="webhook"
                value={options.webhook}
                onChange={(e) => setOptions({ ...options, webhook: e.target.value })}
                placeholder="https://discord.com/api/webhooks/..."
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              />
              <p className="mt-1 text-sm text-gray-500">
                Add a Discord webhook URL to receive scan notifications
              </p>
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium text-gray-700">Scan Options</div>
              <div className="grid grid-cols-2 gap-4">
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={options.skip_ports}
                    onChange={() => setOptions({ ...options, skip_ports: !options.skip_ports })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span>Skip Ports</span>
                </label>
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={options.skip_fuzz}
                    onChange={() => setOptions({ ...options, skip_fuzz: !options.skip_fuzz })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span>Skip Fuzz</span>
                </label>
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={options.skip_sqli}
                    onChange={() => setOptions({ ...options, skip_sqli: !options.skip_sqli })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span>Skip SQLi</span>
                </label>
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={options.skip_paramx}
                    onChange={() => setOptions({ ...options, skip_paramx: !options.skip_paramx })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span>Skip ParamX</span>
                </label>
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={options.verbose}
                    onChange={() => setOptions({ ...options, verbose: !options.verbose })}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span>Verbose</span>
                </label>
              </div>
            </div>

            <div className="flex gap-4">
              <button
                onClick={startScan}
                disabled={loading}
                className={`flex-1 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline ${
                  loading ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {loading ? (
                  <span className="flex items-center justify-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Scanning...
                  </span>
                ) : (
                  'Start Scan'
                )}
              </button>
              
              {loading && (
                <button
                  onClick={stopScan}
                  className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                >
                  Stop Scan
                </button>
              )}
            </div>
          </div>
        </div>

        {output && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold mb-4">Scan Output</h2>
            <pre className="bg-gray-900 text-green-400 p-4 rounded overflow-x-auto">
              {output}
            </pre>
          </div>
        )}
      </div>
    </Layout>
  )
}

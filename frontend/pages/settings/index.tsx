import React, { useState } from 'react';
import Layout from '../../components/Layout';

interface ToolConfig {
  name: string;
  enabled: boolean;
  path: string;
  version: string;
  options: Record<string, any>;
}

interface NotificationConfig {
  discord: {
    enabled: boolean;
    webhook: string;
  };
  slack: {
    enabled: boolean;
    webhook: string;
  };
}

const SettingsPage = () => {
  const [tools, setTools] = useState<ToolConfig[]>([
    {
      name: 'subfinder',
      enabled: true,
      path: '/usr/local/bin/subfinder',
      version: '2.5.3',
      options: {
        threads: 10,
        timeout: 30,
      }
    },
    {
      name: 'nuclei',
      enabled: true,
      path: '/usr/local/bin/nuclei',
      version: '2.8.9',
      options: {
        concurrency: 25,
        rate_limit: 150,
      }
    },
    // Add more tools
  ]);

  const [notifications, setNotifications] = useState<NotificationConfig>({
    discord: {
      enabled: true,
      webhook: 'https://discord.com/api/webhooks/...'
    },
    slack: {
      enabled: false,
      webhook: ''
    }
  });

  const [scanDefaults, setScanDefaults] = useState({
    skipPorts: false,
    skipFuzz: false,
    skipSQLi: false,
    skipParamX: false,
    verbose: true,
    maxDepth: 3,
    timeout: 300,
  });

  const handleToolToggle = (toolName: string) => {
    setTools(tools.map(tool => 
      tool.name === toolName ? { ...tool, enabled: !tool.enabled } : tool
    ));
  };

  const handleToolOptionChange = (toolName: string, option: string, value: any) => {
    setTools(tools.map(tool => 
      tool.name === toolName 
        ? { ...tool, options: { ...tool.options, [option]: value } }
        : tool
    ));
  };

  const handleNotificationToggle = (platform: 'discord' | 'slack') => {
    setNotifications({
      ...notifications,
      [platform]: {
        ...notifications[platform],
        enabled: !notifications[platform].enabled
      }
    });
  };

  const handleWebhookChange = (platform: 'discord' | 'slack', webhook: string) => {
    setNotifications({
      ...notifications,
      [platform]: {
        ...notifications[platform],
        webhook
      }
    });
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Tool Configuration
            </h3>
            <div className="mt-6 space-y-6">
              {tools.map((tool) => (
                <div key={tool.name} className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        checked={tool.enabled}
                        onChange={() => handleToolToggle(tool.name)}
                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                      />
                      <label className="ml-3 block text-sm font-medium text-gray-700">
                        {tool.name}
                        <span className="ml-2 text-sm text-gray-500">v{tool.version}</span>
                      </label>
                    </div>
                    <span className="text-sm text-gray-500">{tool.path}</span>
                  </div>
                  {tool.enabled && (
                    <div className="ml-7 grid grid-cols-2 gap-4">
                      {Object.entries(tool.options).map(([key, value]) => (
                        <div key={key}>
                          <label className="block text-sm font-medium text-gray-700">
                            {key}
                          </label>
                          <input
                            type="number"
                            value={value}
                            onChange={(e) => handleToolOptionChange(tool.name, key, parseInt(e.target.value))}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Notifications
            </h3>
            <div className="mt-6 space-y-6">
              <div className="space-y-4">
                <div className="flex items-start">
                  <div className="flex items-center h-5">
                    <input
                      type="checkbox"
                      checked={notifications.discord.enabled}
                      onChange={() => handleNotificationToggle('discord')}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    />
                  </div>
                  <div className="ml-3">
                    <label className="block text-sm font-medium text-gray-700">
                      Discord Notifications
                    </label>
                    {notifications.discord.enabled && (
                      <input
                        type="text"
                        value={notifications.discord.webhook}
                        onChange={(e) => handleWebhookChange('discord', e.target.value)}
                        placeholder="Discord Webhook URL"
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                      />
                    )}
                  </div>
                </div>

                <div className="flex items-start">
                  <div className="flex items-center h-5">
                    <input
                      type="checkbox"
                      checked={notifications.slack.enabled}
                      onChange={() => handleNotificationToggle('slack')}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    />
                  </div>
                  <div className="ml-3">
                    <label className="block text-sm font-medium text-gray-700">
                      Slack Notifications
                    </label>
                    {notifications.slack.enabled && (
                      <input
                        type="text"
                        value={notifications.slack.webhook}
                        onChange={(e) => handleWebhookChange('slack', e.target.value)}
                        placeholder="Slack Webhook URL"
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                      />
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Scan Defaults
            </h3>
            <div className="mt-6 space-y-6">
              <div className="grid grid-cols-1 gap-y-6 gap-x-4 sm:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Max Depth
                  </label>
                  <input
                    type="number"
                    value={scanDefaults.maxDepth}
                    onChange={(e) => setScanDefaults({ ...scanDefaults, maxDepth: parseInt(e.target.value) })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    value={scanDefaults.timeout}
                    onChange={(e) => setScanDefaults({ ...scanDefaults, timeout: parseInt(e.target.value) })}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                  />
                </div>
              </div>

              <div className="space-y-4">
                {Object.entries(scanDefaults)
                  .filter(([key]) => typeof scanDefaults[key as keyof typeof scanDefaults] === 'boolean')
                  .map(([key, value]) => (
                    <div key={key} className="flex items-start">
                      <div className="flex items-center h-5">
                        <input
                          type="checkbox"
                          checked={value}
                          onChange={() => setScanDefaults({ ...scanDefaults, [key]: !value })}
                          className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                        />
                      </div>
                      <div className="ml-3 text-sm">
                        <label className="font-medium text-gray-700">
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </label>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default SettingsPage;

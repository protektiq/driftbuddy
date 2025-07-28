import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import axios from 'axios';

interface UserProfile {
  id: number;
  email: string;
  username: string;
  first_name?: string;
  last_name?: string;
  role: string;
  organization_id?: number;
  is_active: boolean;
  created_at: string;
}

interface SystemSettings {
  notifications_enabled: boolean;
  email_notifications: boolean;
  scan_auto_run: boolean;
  report_auto_generate: boolean;
  theme: 'light' | 'dark' | 'auto';
  language: string;
}

interface IntegrationConfig {
  aws_access_key?: string;
  aws_secret_key?: string;
  azure_tenant_id?: string;
  azure_client_id?: string;
  gcp_project_id?: string;
  gcp_service_account_key?: string;
  openai_api_key?: string;
  jira_url?: string;
  jira_username?: string;
  jira_api_token?: string;
  slack_webhook_url?: string;
}

const Settings: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Profile state
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [profileForm, setProfileForm] = useState({
    first_name: '',
    last_name: '',
    email: '',
    current_password: '',
    new_password: '',
    confirm_password: ''
  });

  // System settings state
  const [systemSettings, setSystemSettings] = useState<SystemSettings>({
    notifications_enabled: true,
    email_notifications: true,
    scan_auto_run: false,
    report_auto_generate: false,
    theme: 'light',
    language: 'en'
  });

  // Integration state
  const [integrations, setIntegrations] = useState<IntegrationConfig>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const [profileResponse, settingsResponse, integrationsResponse] = await Promise.all([
        axios.get('/api/settings/profile'),
        axios.get('/api/settings/system'),
        axios.get('/api/settings/integrations')
      ]);
      
      setProfile(profileResponse.data);
      setProfileForm({
        first_name: profileResponse.data.first_name || '',
        last_name: profileResponse.data.last_name || '',
        email: profileResponse.data.email,
        current_password: '',
        new_password: '',
        confirm_password: ''
      });
      setSystemSettings(settingsResponse.data);
      setIntegrations(integrationsResponse.data);
    } catch (err) {
      console.error('Failed to load settings:', err);
      setError('Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const handleProfileUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.put('/api/settings/profile', {
        first_name: profileForm.first_name,
        last_name: profileForm.last_name,
        email: profileForm.email
      });
      setSuccess('Profile updated successfully');
    } catch (err) {
      setError('Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (profileForm.new_password !== profileForm.confirm_password) {
      setError('New passwords do not match');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.put('/api/settings/password', {
        current_password: profileForm.current_password,
        new_password: profileForm.new_password
      });
      setSuccess('Password changed successfully');
      setProfileForm(prev => ({
        ...prev,
        current_password: '',
        new_password: '',
        confirm_password: ''
      }));
    } catch (err) {
      setError('Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleSystemSettingsUpdate = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.put('/api/settings/system', systemSettings);
      setSuccess('System settings updated successfully');
    } catch (err) {
      setError('Failed to update system settings');
    } finally {
      setLoading(false);
    }
  };

  const handleIntegrationUpdate = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.put('/api/settings/integrations', integrations);
      setSuccess('Integration settings updated successfully');
    } catch (err) {
      setError('Failed to update integration settings');
    } finally {
      setLoading(false);
    }
  };

  const toggleSecret = (key: string) => {
    setShowSecrets(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const maskSecret = (secret: string) => {
    if (!secret) return '';
    return '•'.repeat(Math.min(secret.length, 20));
  };

  if (loading && !profile) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading settings...</div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="py-6">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
          <p className="text-gray-600">Manage your account and system preferences</p>
        </div>

        {/* Success/Error Messages */}
        {success && (
          <div className="mb-4 bg-green-50 border border-green-200 rounded-md p-4">
            <div className="text-green-800">{success}</div>
          </div>
        )}
        {error && (
          <div className="mb-4 bg-red-50 border border-red-200 rounded-md p-4">
            <div className="text-red-800">{error}</div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="border-b border-gray-200 mb-8">
          <nav className="-mb-px flex space-x-8">
            {[
              { id: 'profile', name: 'Profile', icon: '👤' },
              { id: 'system', name: 'System', icon: '⚙️' },
              { id: 'integrations', name: 'Integrations', icon: '🔗' },
              { id: 'security', name: 'Security', icon: '🔒' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Profile Tab */}
        {activeTab === 'profile' && (
          <div className="space-y-8">
            {/* Profile Information */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-medium text-gray-900">Profile Information</h2>
              </div>
              <div className="px-6 py-4">
                <form onSubmit={handleProfileUpdate} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">First Name</label>
                      <input
                        type="text"
                        value={profileForm.first_name}
                        onChange={(e) => setProfileForm(prev => ({ ...prev, first_name: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Last Name</label>
                      <input
                        type="text"
                        value={profileForm.last_name}
                        onChange={(e) => setProfileForm(prev => ({ ...prev, last_name: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Email</label>
                    <input
                      type="email"
                      value={profileForm.email}
                      onChange={(e) => setProfileForm(prev => ({ ...prev, email: e.target.value }))}
                      className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={loading}
                      className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                    >
                      {loading ? 'Updating...' : 'Update Profile'}
                    </button>
                  </div>
                </form>
              </div>
            </div>

            {/* Change Password */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-medium text-gray-900">Change Password</h2>
              </div>
              <div className="px-6 py-4">
                <form onSubmit={handlePasswordChange} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Current Password</label>
                    <input
                      type="password"
                      value={profileForm.current_password}
                      onChange={(e) => setProfileForm(prev => ({ ...prev, current_password: e.target.value }))}
                      className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">New Password</label>
                    <input
                      type="password"
                      value={profileForm.new_password}
                      onChange={(e) => setProfileForm(prev => ({ ...prev, new_password: e.target.value }))}
                      className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Confirm New Password</label>
                    <input
                      type="password"
                      value={profileForm.confirm_password}
                      onChange={(e) => setProfileForm(prev => ({ ...prev, confirm_password: e.target.value }))}
                      className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={loading}
                      className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                    >
                      {loading ? 'Changing...' : 'Change Password'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* System Settings Tab */}
        {activeTab === 'system' && (
          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-medium text-gray-900">System Preferences</h2>
            </div>
            <div className="px-6 py-4 space-y-6">
              <div>
                <h3 className="text-md font-medium text-gray-900 mb-4">Notifications</h3>
                <div className="space-y-3">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={systemSettings.notifications_enabled}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, notifications_enabled: e.target.checked }))}
                      className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Enable notifications</span>
                  </label>
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={systemSettings.email_notifications}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, email_notifications: e.target.checked }))}
                      className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Email notifications</span>
                  </label>
                </div>
              </div>

              <div>
                <h3 className="text-md font-medium text-gray-900 mb-4">Automation</h3>
                <div className="space-y-3">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={systemSettings.scan_auto_run}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, scan_auto_run: e.target.checked }))}
                      className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Auto-run scheduled scans</span>
                  </label>
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={systemSettings.report_auto_generate}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, report_auto_generate: e.target.checked }))}
                      className="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Auto-generate reports</span>
                  </label>
                </div>
              </div>

              <div>
                <h3 className="text-md font-medium text-gray-900 mb-4">Appearance</h3>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Theme</label>
                    <select
                      value={systemSettings.theme}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, theme: e.target.value as any }))}
                      className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    >
                      <option value="light">Light</option>
                      <option value="dark">Dark</option>
                      <option value="auto">Auto</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Language</label>
                    <select
                      value={systemSettings.language}
                      onChange={(e) => setSystemSettings(prev => ({ ...prev, language: e.target.value }))}
                      className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    >
                      <option value="en">English</option>
                      <option value="es">Spanish</option>
                      <option value="fr">French</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleSystemSettingsUpdate}
                  disabled={loading}
                  className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                >
                  {loading ? 'Saving...' : 'Save Settings'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Integrations Tab */}
        {activeTab === 'integrations' && (
          <div className="space-y-8">
            {/* Cloud Providers */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-medium text-gray-900">Cloud Providers</h2>
              </div>
              <div className="px-6 py-4 space-y-4">
                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-2">AWS</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Access Key</label>
                      <div className="relative">
                        <input
                          type={showSecrets.aws_access_key ? 'text' : 'password'}
                          value={integrations.aws_access_key || ''}
                          onChange={(e) => setIntegrations(prev => ({ ...prev, aws_access_key: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 pr-10 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          placeholder={integrations.aws_access_key ? maskSecret(integrations.aws_access_key) : 'Enter AWS Access Key'}
                        />
                        <button
                          type="button"
                          onClick={() => toggleSecret('aws_access_key')}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showSecrets.aws_access_key ? '👁️' : '👁️‍🗨️'}
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Secret Key</label>
                      <div className="relative">
                        <input
                          type={showSecrets.aws_secret_key ? 'text' : 'password'}
                          value={integrations.aws_secret_key || ''}
                          onChange={(e) => setIntegrations(prev => ({ ...prev, aws_secret_key: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 pr-10 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          placeholder={integrations.aws_secret_key ? maskSecret(integrations.aws_secret_key) : 'Enter AWS Secret Key'}
                        />
                        <button
                          type="button"
                          onClick={() => toggleSecret('aws_secret_key')}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showSecrets.aws_secret_key ? '👁️' : '👁️‍🗨️'}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-2">Azure</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Tenant ID</label>
                      <input
                        type="text"
                        value={integrations.azure_tenant_id || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, azure_tenant_id: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Enter Azure Tenant ID"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Client ID</label>
                      <input
                        type="text"
                        value={integrations.azure_client_id || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, azure_client_id: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Enter Azure Client ID"
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-2">Google Cloud</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Project ID</label>
                      <input
                        type="text"
                        value={integrations.gcp_project_id || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, gcp_project_id: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Enter GCP Project ID"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Service Account Key</label>
                      <textarea
                        value={integrations.gcp_service_account_key || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, gcp_service_account_key: e.target.value }))}
                        rows={3}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Enter GCP Service Account JSON"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* External Services */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-medium text-gray-900">External Services</h2>
              </div>
              <div className="px-6 py-4 space-y-4">
                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-2">OpenAI</h3>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">API Key</label>
                    <div className="relative">
                      <input
                        type={showSecrets.openai_api_key ? 'text' : 'password'}
                        value={integrations.openai_api_key || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, openai_api_key: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 pr-10 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder={integrations.openai_api_key ? maskSecret(integrations.openai_api_key) : 'Enter OpenAI API Key'}
                      />
                      <button
                        type="button"
                        onClick={() => toggleSecret('openai_api_key')}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      >
                        {showSecrets.openai_api_key ? '👁️' : '👁️‍🗨️'}
                      </button>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-2">Jira</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">URL</label>
                      <input
                        type="url"
                        value={integrations.jira_url || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, jira_url: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="https://your-domain.atlassian.net"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Username</label>
                      <input
                        type="text"
                        value={integrations.jira_username || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, jira_username: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Enter Jira username"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700">API Token</label>
                      <div className="relative">
                        <input
                          type={showSecrets.jira_api_token ? 'text' : 'password'}
                          value={integrations.jira_api_token || ''}
                          onChange={(e) => setIntegrations(prev => ({ ...prev, jira_api_token: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 pr-10 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          placeholder={integrations.jira_api_token ? maskSecret(integrations.jira_api_token) : 'Enter Jira API Token'}
                        />
                        <button
                          type="button"
                          onClick={() => toggleSecret('jira_api_token')}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center"
                        >
                          {showSecrets.jira_api_token ? '👁️' : '👁️‍🗨️'}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-2">Slack</h3>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Webhook URL</label>
                    <div className="relative">
                      <input
                        type={showSecrets.slack_webhook_url ? 'text' : 'password'}
                        value={integrations.slack_webhook_url || ''}
                        onChange={(e) => setIntegrations(prev => ({ ...prev, slack_webhook_url: e.target.value }))}
                        className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 pr-10 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder={integrations.slack_webhook_url ? maskSecret(integrations.slack_webhook_url) : 'Enter Slack Webhook URL'}
                      />
                      <button
                        type="button"
                        onClick={() => toggleSecret('slack_webhook_url')}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      >
                        {showSecrets.slack_webhook_url ? '👁️' : '👁️‍🗨️'}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={handleIntegrationUpdate}
                    disabled={loading}
                    className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                  >
                    {loading ? 'Saving...' : 'Save Integrations'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && (
          <div className="space-y-8">
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-medium text-gray-900">Security Settings</h2>
              </div>
              <div className="px-6 py-4 space-y-6">
                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-4">Account Security</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-700">Two-Factor Authentication</p>
                        <p className="text-sm text-gray-500">Add an extra layer of security to your account</p>
                      </div>
                      <button className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700">
                        Enable 2FA
                      </button>
                    </div>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-700">Session Management</p>
                        <p className="text-sm text-gray-500">View and manage active sessions</p>
                      </div>
                      <button className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700">
                        Manage Sessions
                      </button>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-md font-medium text-gray-900 mb-4">Danger Zone</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-700">Delete Account</p>
                        <p className="text-sm text-gray-500">Permanently delete your account and all data</p>
                      </div>
                      <button className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700">
                        Delete Account
                      </button>
                    </div>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-700">Logout</p>
                        <p className="text-sm text-gray-500">Sign out of your current session</p>
                      </div>
                      <button 
                        onClick={logout}
                        className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700"
                      >
                        Logout
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Settings; 
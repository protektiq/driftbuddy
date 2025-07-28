import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

interface Scan {
  id: number;
  name: string;
  description: string;
  scan_type: string;
  target_path: string;
  status: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  findings_count?: number;
  risk_score?: number;
}

interface ScanCreate {
  name: string;
  description: string;
  scan_type: string;
  target_path: string;
  configuration?: Record<string, any>;
}

const Scans: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Form state
  const [formData, setFormData] = useState<ScanCreate>({
    name: '',
    description: '',
    scan_type: 'kics',
    target_path: '',
    configuration: {}
  });

  // Load scans on component mount
  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/scans');
      setScans(response.data);
    } catch (err) {
      console.error('Failed to load scans:', err);
      setError('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError('');
    setSuccess('');

    try {
      await axios.post('/api/scans', formData);
      setSuccess('Scan created successfully!');
      setShowCreateForm(false);
      setFormData({
        name: '',
        description: '',
        scan_type: 'kics',
        target_path: '',
        configuration: {}
      });
      loadScans(); // Reload the list
    } catch (err: any) {
      console.error('Failed to create scan:', err);
      setError(err.response?.data?.detail || 'Failed to create scan');
    } finally {
      setCreating(false);
    }
  };

  const handleRunScan = async (scanId: number) => {
    try {
      await axios.post(`/api/scans/${scanId}/run`);
      setSuccess('Scan started successfully!');
      loadScans(); // Reload to get updated status
    } catch (err: any) {
      console.error('Failed to run scan:', err);
      setError(err.response?.data?.detail || 'Failed to run scan');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'running':
        return 'bg-blue-100 text-blue-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="py-6">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Security Scans</h1>
            <p className="text-gray-600">Create and manage security scans</p>
          </div>
          <button
            onClick={() => setShowCreateForm(true)}
            className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700"
          >
            Create New Scan
          </button>
        </div>

        {/* Success/Error Messages */}
        {success && (
          <div className="mb-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded">
            {success}
          </div>
        )}
        {error && (
          <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
            {error}
          </div>
        )}

        {/* Create Scan Form */}
        {showCreateForm && (
          <div className="mb-6 p-6 bg-white rounded-lg shadow">
            <h2 className="text-lg font-semibold mb-4">Create New Scan</h2>
            <form onSubmit={handleCreateScan}>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Scan Name
                  </label>
                  <input
                    type="text"
                    required
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    placeholder="My Security Scan"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Scan Type
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={formData.scan_type}
                    onChange={(e) => setFormData({...formData, scan_type: e.target.value})}
                  >
                    <option value="kics">KICS (Infrastructure as Code)</option>
                    <option value="cloud">Cloud Security</option>
                    <option value="container">Container Security</option>
                    <option value="custom">Custom Scan</option>
                  </select>
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Description
                  </label>
                  <textarea
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    rows={3}
                    value={formData.description}
                    onChange={(e) => setFormData({...formData, description: e.target.value})}
                    placeholder="Describe what this scan will check..."
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Target Path
                  </label>
                  <input
                    type="text"
                    required
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    value={formData.target_path}
                    onChange={(e) => setFormData({...formData, target_path: e.target.value})}
                    placeholder="/path/to/your/code or https://github.com/user/repo"
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-4">
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
                >
                  {creating ? 'Creating...' : 'Create Scan'}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Scans List */}
        <div className="bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Recent Scans</h3>
          </div>
          {loading ? (
            <div className="p-6 text-center text-gray-500">Loading scans...</div>
          ) : scans.length === 0 ? (
            <div className="p-6 text-center text-gray-500">
              No scans found. Create your first scan to get started.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Scan
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Findings
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-gray-900">
                            {scan.name}
                          </div>
                          <div className="text-sm text-gray-500">
                            {scan.description}
                          </div>
                        </div>
                      </td>
                                             <td className="px-6 py-4 whitespace-nowrap">
                         <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                           {scan.scan_type === 'kics' ? 'IaC' : scan.scan_type}
                         </span>
                       </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {formatDate(scan.created_at)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {scan.findings_count || 0} findings
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex space-x-2">
                          {scan.status === 'pending' && (
                            <button
                              onClick={() => handleRunScan(scan.id)}
                              className="text-indigo-600 hover:text-indigo-900"
                            >
                              Run
                            </button>
                          )}
                                                     <button 
                             onClick={() => navigate(`/scans/${scan.id}/results`)}
                             className="text-gray-600 hover:text-gray-900"
                           >
                             View
                           </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Scans; 
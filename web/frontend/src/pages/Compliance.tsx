import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import axios from 'axios';

interface ComplianceFramework {
  id: number;
  name: string;
  version: string;
  description: string;
  category: string;
  is_active: boolean;
  control_count: number;
  created_at: string;
}

interface ComplianceControl {
  id: number;
  framework_id: number;
  control_id: string;
  title: string;
  description: string;
  category: string;
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_assessed';
  evidence_count: number;
  last_updated: string;
  assigned_to?: string;
}

interface AuditEvent {
  id: number;
  user_id: number;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string;
  timestamp: string;
  ip_address: string;
}

interface Assessment {
  id: number;
  framework_id: number;
  framework_name: string;
  status: 'in_progress' | 'completed' | 'overdue';
  start_date: string;
  end_date: string;
  assessor: string;
  score: number;
  total_controls: number;
  compliant_controls: number;
}

const Compliance: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('frameworks');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // State for different sections
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<number | null>(null);

  // Form states
  const [showCreateFramework, setShowCreateFramework] = useState(false);
  const [showCreateAssessment, setShowCreateAssessment] = useState(false);
  const [frameworkForm, setFrameworkForm] = useState({
    name: '',
    version: '',
    description: ''
  });
  const [assessmentForm, setAssessmentForm] = useState({
    framework_id: '',
    start_date: '',
    end_date: '',
    assessor: ''
  });

  useEffect(() => {
    loadComplianceData();
  }, []);

  const loadComplianceData = async () => {
    setLoading(true);
    try {
      const [frameworksResponse, controlsResponse, auditResponse, assessmentsResponse] = await Promise.all([
        axios.get('/api/compliance/frameworks'),
        axios.get('/api/compliance/controls'),
        axios.get('/api/compliance/audit-events'),
        axios.get('/api/compliance/assessments')
      ]);
      
      console.log('Frameworks response:', frameworksResponse.data);
      console.log('Controls response:', controlsResponse.data);
      console.log('Audit response:', auditResponse.data);
      console.log('Assessments response:', assessmentsResponse.data);
      
      // Safely handle the response data
      const frameworksData = Array.isArray(frameworksResponse.data) ? frameworksResponse.data : [];
      const controlsData = Array.isArray(controlsResponse.data) ? controlsResponse.data : [];
      const auditData = Array.isArray(auditResponse.data) ? auditResponse.data : [];
      const assessmentsData = Array.isArray(assessmentsResponse.data) ? assessmentsResponse.data : [];
      
      setFrameworks(frameworksData);
      setControls(controlsData);
      setAuditEvents(auditData);
      setAssessments(assessmentsData);
    } catch (err) {
      console.error('Failed to load compliance data:', err);
      setError('Failed to load compliance data');
      // Set empty arrays on error
      setFrameworks([]);
      setControls([]);
      setAuditEvents([]);
      setAssessments([]);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateFramework = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.post('/api/compliance/frameworks', frameworkForm);
      setSuccess('Framework created successfully');
      setShowCreateFramework(false);
      setFrameworkForm({ name: '', version: '', description: '' });
      loadComplianceData();
    } catch (err) {
      setError('Failed to create framework');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await axios.post('/api/compliance/assessments', assessmentForm);
      setSuccess('Assessment created successfully');
      setShowCreateAssessment(false);
      setAssessmentForm({ framework_id: '', start_date: '', end_date: '', assessor: '' });
      loadComplianceData();
    } catch (err) {
      setError('Failed to create assessment');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string | undefined | null) => {
    if (!status) return 'text-gray-600 bg-gray-100';
    
    switch (status.toLowerCase()) {
      case 'active':
      case 'compliant':
      case 'completed':
        return 'text-green-600 bg-green-100';
      case 'inactive':
      case 'non_compliant':
      case 'overdue':
        return 'text-red-600 bg-red-100';
      case 'partial':
      case 'in_progress':
        return 'text-yellow-600 bg-yellow-100';
      case 'draft':
      case 'not_assessed':
        return 'text-gray-600 bg-gray-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string | undefined | null) => {
    if (!status) return '❓';
    
    switch (status.toLowerCase()) {
      case 'active':
      case 'compliant':
      case 'completed':
        return '✅';
      case 'inactive':
      case 'non_compliant':
      case 'overdue':
        return '❌';
      case 'partial':
      case 'in_progress':
        return '⚠️';
      case 'draft':
      case 'not_assessed':
        return '📝';
      default:
        return '❓';
    }
  };

  const formatDate = (dateString: string | undefined | null) => {
    if (!dateString) return 'N/A';
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return 'Invalid Date';
    }
  };

  const filteredControls = selectedFramework 
    ? (controls || []).filter(control => control.framework_id === selectedFramework)
    : (controls || []);

  if (loading && (!frameworks || frameworks.length === 0)) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading compliance data...</div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="py-6">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Compliance Management</h1>
          <p className="text-gray-600">Manage compliance frameworks, controls, and assessments</p>
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
              { id: 'frameworks', name: 'Frameworks', icon: '📋' },
              { id: 'controls', name: 'Controls', icon: '🔒' },
              { id: 'assessments', name: 'Assessments', icon: '📊' },
              { id: 'audit', name: 'Audit Trail', icon: '📝' }
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

        {/* Frameworks Tab */}
        {activeTab === 'frameworks' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-medium text-gray-900">Compliance Frameworks</h2>
              <button
                onClick={() => setShowCreateFramework(true)}
                className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700"
              >
                Add Framework
              </button>
            </div>

            {/* Create Framework Modal */}
            {showCreateFramework && (
              <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
                <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                  <div className="mt-3">
                    <h3 className="text-lg font-medium text-gray-900 mb-4">Create New Framework</h3>
                    <form onSubmit={handleCreateFramework} className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Framework Name</label>
                        <input
                          type="text"
                          value={frameworkForm.name}
                          onChange={(e) => setFrameworkForm(prev => ({ ...prev, name: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Version</label>
                        <input
                          type="text"
                          value={frameworkForm.version}
                          onChange={(e) => setFrameworkForm(prev => ({ ...prev, version: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Description</label>
                        <textarea
                          value={frameworkForm.description}
                          onChange={(e) => setFrameworkForm(prev => ({ ...prev, description: e.target.value }))}
                          rows={3}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        />
                      </div>
                      <div className="flex justify-end space-x-3">
                        <button
                          type="button"
                          onClick={() => setShowCreateFramework(false)}
                          className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-400"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={loading}
                          className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                        >
                          {loading ? 'Creating...' : 'Create Framework'}
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              </div>
            )}

            {/* Frameworks List */}
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200">
                {Array.isArray(frameworks) ? frameworks.map((framework) => (
                  <li key={framework.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <div className="w-8 h-8 bg-indigo-500 rounded-md flex items-center justify-center">
                            <span className="text-white text-sm font-medium">📋</span>
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="flex items-center">
                            <h3 className="text-sm font-medium text-gray-900">{framework.name}</h3>
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                              v{framework.version}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500">{framework.description}</p>
                          <div className="mt-1 flex items-center space-x-4 text-xs text-gray-500">
                            <span>{framework.control_count} controls</span>
                            <span>Category: {framework.category}</span>
                            <span>Created: {formatDate(framework.created_at)}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(framework.is_active ? 'active' : 'inactive')}`}>
                          {getStatusIcon(framework.is_active ? 'active' : 'inactive')} {framework.is_active ? 'Active' : 'Inactive'}
                        </span>
                        <button className="text-indigo-600 hover:text-indigo-900 text-sm font-medium">
                          View
                        </button>
                      </div>
                    </div>
                  </li>
                )) : (
                  <li className="px-6 py-4 text-center text-gray-500">
                    No frameworks available
                  </li>
                )}
              </ul>
            </div>
          </div>
        )}

        {/* Controls Tab */}
        {activeTab === 'controls' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-medium text-gray-900">Compliance Controls</h2>
              <div className="flex items-center space-x-4">
                <select
                  value={selectedFramework || ''}
                  onChange={(e) => setSelectedFramework(e.target.value ? Number(e.target.value) : null)}
                  className="border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                >
                  <option value="">All Frameworks</option>
                  {Array.isArray(frameworks) ? frameworks.map((framework) => (
                    <option key={framework.id} value={framework.id}>
                      {framework.name}
                    </option>
                  )) : null}
                </select>
              </div>
            </div>

            {/* Controls List */}
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200">
                {filteredControls.map((control) => (
                  <li key={control.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <div className="w-8 h-8 bg-blue-500 rounded-md flex items-center justify-center">
                            <span className="text-white text-sm font-medium">🔒</span>
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="flex items-center">
                            <h3 className="text-sm font-medium text-gray-900">{control.control_id}: {control.title}</h3>
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                              {control.category}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500">{control.description}</p>
                          <div className="mt-1 flex items-center space-x-4 text-xs text-gray-500">
                            <span>{control.evidence_count} evidence items</span>
                            <span>Updated: {formatDate(control.last_updated)}</span>
                            {control.assigned_to && <span>Assigned to: {control.assigned_to}</span>}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(control.status)}`}>
                          {getStatusIcon(control.status)} {control.status.replace('_', ' ')}
                        </span>
                        <button className="text-indigo-600 hover:text-indigo-900 text-sm font-medium">
                          View
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Assessments Tab */}
        {activeTab === 'assessments' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-medium text-gray-900">Compliance Assessments</h2>
              <button
                onClick={() => setShowCreateAssessment(true)}
                className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700"
              >
                New Assessment
              </button>
            </div>

            {/* Create Assessment Modal */}
            {showCreateAssessment && (
              <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
                <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                  <div className="mt-3">
                    <h3 className="text-lg font-medium text-gray-900 mb-4">Create New Assessment</h3>
                    <form onSubmit={handleCreateAssessment} className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Framework</label>
                        <select
                          value={assessmentForm.framework_id}
                          onChange={(e) => setAssessmentForm(prev => ({ ...prev, framework_id: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        >
                          <option value="">Select Framework</option>
                          {Array.isArray(frameworks) ? frameworks.map((framework) => (
                            <option key={framework.id} value={framework.id}>
                              {framework.name}
                            </option>
                          )) : null}
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Start Date</label>
                        <input
                          type="date"
                          value={assessmentForm.start_date}
                          onChange={(e) => setAssessmentForm(prev => ({ ...prev, start_date: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">End Date</label>
                        <input
                          type="date"
                          value={assessmentForm.end_date}
                          onChange={(e) => setAssessmentForm(prev => ({ ...prev, end_date: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Assessor</label>
                        <input
                          type="text"
                          value={assessmentForm.assessor}
                          onChange={(e) => setAssessmentForm(prev => ({ ...prev, assessor: e.target.value }))}
                          className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                          required
                        />
                      </div>
                      <div className="flex justify-end space-x-3">
                        <button
                          type="button"
                          onClick={() => setShowCreateAssessment(false)}
                          className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-400"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={loading}
                          className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                        >
                          {loading ? 'Creating...' : 'Create Assessment'}
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              </div>
            )}

            {/* Assessments List */}
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200">
                {assessments.map((assessment) => (
                  <li key={assessment.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <div className="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
                            <span className="text-white text-sm font-medium">📊</span>
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="flex items-center">
                            <h3 className="text-sm font-medium text-gray-900">{assessment.framework_name} Assessment</h3>
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                              {assessment.assessor}
                            </span>
                          </div>
                          <div className="mt-1 flex items-center space-x-4 text-xs text-gray-500">
                            <span>{assessment.compliant_controls}/{assessment.total_controls} controls compliant</span>
                            <span>Score: {assessment.score}%</span>
                            <span>{formatDate(assessment.start_date)} - {formatDate(assessment.end_date)}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(assessment.status)}`}>
                          {getStatusIcon(assessment.status)} {assessment.status.replace('_', ' ')}
                        </span>
                        <button className="text-indigo-600 hover:text-indigo-900 text-sm font-medium">
                          View
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Audit Trail Tab */}
        {activeTab === 'audit' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-medium text-gray-900">Audit Trail</h2>
              <button className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700">
                Export Log
              </button>
            </div>

            {/* Audit Events List */}
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200">
                {auditEvents.map((event) => (
                  <li key={event.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          <div className="w-8 h-8 bg-gray-500 rounded-md flex items-center justify-center">
                            <span className="text-white text-sm font-medium">📝</span>
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="flex items-center">
                            <h3 className="text-sm font-medium text-gray-900">{event.action}</h3>
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                              {event.resource_type}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500">{event.details}</p>
                          <div className="mt-1 flex items-center space-x-4 text-xs text-gray-500">
                            <span>{event.user_email}</span>
                            <span>{formatDate(event.timestamp)}</span>
                            <span>IP: {event.ip_address}</span>
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-gray-500">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Compliance; 
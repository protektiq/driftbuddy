import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';
import axios from 'axios';

interface Finding {
  id: number;
  title: string;
  description: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  file_path?: string;
  line_number?: number;
  remediation: string;
  cwe_id?: string;
  cvss_score?: number;
  created_at: string;
}

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
  scan_metadata?: Record<string, any>;
}

const ScanResults: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [sortBy, setSortBy] = useState<string>('severity');
  const [exporting, setExporting] = useState(false);

  const loadScanDetails = useCallback(async () => {
    setLoading(true);
    try {
      const [scanResponse, findingsResponse] = await Promise.all([
        axios.get(`/api/scans/${scanId}`),
        axios.get(`/api/scans/${scanId}/findings`)
      ]);
      
      setScan(scanResponse.data);
      setFindings(findingsResponse.data);
    } catch (err: any) {
      console.error('Failed to load scan details:', err);
      setError(err.response?.data?.detail || 'Failed to load scan details');
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    if (scanId) {
      loadScanDetails();
    }
  }, [scanId, loadScanDetails]);

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'HIGH':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'INFO':
        return 'bg-gray-100 text-gray-800 border-gray-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'HIGH':
        return '🔴';
      case 'MEDIUM':
        return '🟡';
      case 'LOW':
        return '🔵';
      case 'INFO':
        return 'ℹ️';
      default:
        return '⚪';
    }
  };

  const filteredAndSortedFindings = findings
    .filter(finding => filterSeverity === 'all' || finding.severity.toLowerCase() === filterSeverity)
    .sort((a, b) => {
      if (sortBy === 'severity') {
        const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
        return severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder];
      }
      if (sortBy === 'date') {
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      }
      return 0;
    });

  const severityCounts = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const handleExport = async (format: string) => {
    setExporting(true);
    try {
      const response = await axios.post(`/api/reports/generate/${scanId}`, {
        format: format
      }, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `scan-${scanId}-results.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error('Export failed:', err);
      setError('Failed to export report');
    } finally {
      setExporting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading scan results...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-red-600">Error: {error}</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Scan not found</div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="py-6">
        {/* Header */}
        <div className="flex justify-between items-start mb-6">
          <div>
            <button
              onClick={() => navigate('/scans')}
              className="text-indigo-600 hover:text-indigo-900 mb-2"
            >
              ← Back to Scans
            </button>
            <h1 className="text-2xl font-bold text-gray-900">{scan.name}</h1>
            <p className="text-gray-600">{scan.description}</p>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => handleExport('pdf')}
              disabled={exporting}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {exporting ? 'Exporting...' : 'Export PDF'}
            </button>
            <button
              onClick={() => handleExport('html')}
              disabled={exporting}
              className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
            >
              {exporting ? 'Exporting...' : 'Export HTML'}
            </button>
          </div>
        </div>

        {/* Scan Summary */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">Scan Summary</h2>
          </div>
          <div className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <dt className="text-sm font-medium text-gray-500">Status</dt>
                <dd className="mt-1 text-sm text-gray-900">{scan.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Scan Type</dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {scan.scan_type === 'kics' ? 'IaC' : scan.scan_type}
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Target Path</dt>
                <dd className="mt-1 text-sm text-gray-900">{scan.target_path}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Created</dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {new Date(scan.created_at).toLocaleString()}
                </dd>
              </div>
            </div>
          </div>
        </div>

        {/* Severity Summary */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">Findings Summary</h2>
          </div>
          <div className="px-6 py-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{severityCounts.HIGH || 0}</div>
                <div className="text-sm text-gray-500">High</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-600">{severityCounts.MEDIUM || 0}</div>
                <div className="text-sm text-gray-500">Medium</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{severityCounts.LOW || 0}</div>
                <div className="text-sm text-gray-500">Low</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-600">{severityCounts.INFO || 0}</div>
                <div className="text-sm text-gray-500">Info</div>
              </div>
            </div>
          </div>
        </div>

        {/* Filters and Controls */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-medium text-gray-900">Findings</h2>
              <div className="flex space-x-4">
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                >
                  <option value="all">All Severities</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                >
                  <option value="severity">Sort by Severity</option>
                  <option value="date">Sort by Date</option>
                </select>
              </div>
            </div>
          </div>

          {/* Findings List */}
          <div className="divide-y divide-gray-200">
            {filteredAndSortedFindings.length === 0 ? (
              <div className="px-6 py-8 text-center text-gray-500">
                No findings match the current filters.
              </div>
            ) : (
              filteredAndSortedFindings.map((finding) => (
                <div key={finding.id} className="px-6 py-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="text-lg">{getSeverityIcon(finding.severity)}</span>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <span className="text-sm text-gray-500">{finding.category}</span>
                        {finding.cvss_score && (
                          <span className="text-sm text-gray-500">CVSS: {finding.cvss_score}</span>
                        )}
                      </div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">{finding.title}</h3>
                      <p className="text-gray-600 mb-3">{finding.description}</p>
                      
                      {finding.file_path && (
                        <div className="mb-3">
                          <span className="text-sm font-medium text-gray-500">File: </span>
                          <span className="text-sm text-gray-900 font-mono">{finding.file_path}</span>
                          {finding.line_number && (
                            <span className="text-sm text-gray-500 ml-2">Line {finding.line_number}</span>
                          )}
                        </div>
                      )}
                      
                      <div className="bg-gray-50 rounded-md p-3 mb-3">
                        <h4 className="text-sm font-medium text-gray-700 mb-1">Remediation</h4>
                        <p className="text-sm text-gray-600">{finding.remediation}</p>
                      </div>
                      
                      {finding.cwe_id && (
                        <div className="text-sm text-gray-500">
                          CWE: {finding.cwe_id}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanResults; 
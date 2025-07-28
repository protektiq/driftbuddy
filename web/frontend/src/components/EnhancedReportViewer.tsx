import React from 'react';

interface ExecutiveSummary {
  total_findings: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  average_risk_score: number;
  max_risk_score: number;
  risk_level: string;
  scan_date: string;
  scan_duration: string;
  files_scanned: number;
}

interface EnhancedReportViewerProps {
  executiveSummary: ExecutiveSummary;
  reportPath?: string;
  onDownload?: () => void;
}

const EnhancedReportViewer: React.FC<EnhancedReportViewerProps> = ({
  executiveSummary,
  reportPath,
  onDownload
}) => {
  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-600 text-white';
      case 'HIGH':
        return 'bg-orange-500 text-white';
      case 'MEDIUM':
        return 'bg-yellow-500 text-black';
      case 'LOW':
        return 'bg-green-500 text-white';
      default:
        return 'bg-gray-500 text-white';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">📊 Executive Summary</h2>
        <p className="text-gray-600">Comprehensive security analysis with risk scoring</p>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-blue-600">{executiveSummary.total_findings}</div>
          <div className="text-sm text-gray-600">Total Findings</div>
        </div>
        
        <div className="bg-red-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-red-600">{executiveSummary.high_severity}</div>
          <div className="text-sm text-gray-600">High Severity</div>
        </div>
        
        <div className="bg-orange-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-orange-600">{executiveSummary.average_risk_score}</div>
          <div className="text-sm text-gray-600">Avg Risk Score</div>
        </div>
        
        <div className="bg-gray-50 p-4 rounded-lg">
          <div className={`inline-flex px-3 py-1 rounded-full text-sm font-semibold ${getRiskLevelColor(executiveSummary.risk_level)}`}>
            {executiveSummary.risk_level}
          </div>
          <div className="text-sm text-gray-600 mt-1">Risk Level</div>
        </div>
      </div>

      {/* Detailed Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div className="bg-gray-50 p-4 rounded-lg">
          <h3 className="font-semibold text-gray-900 mb-2">Severity Breakdown</h3>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">High Severity:</span>
              <span className="font-semibold text-red-600">{executiveSummary.high_severity}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Medium Severity:</span>
              <span className="font-semibold text-orange-600">{executiveSummary.medium_severity}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Low Severity:</span>
              <span className="font-semibold text-green-600">{executiveSummary.low_severity}</span>
            </div>
          </div>
        </div>

        <div className="bg-gray-50 p-4 rounded-lg">
          <h3 className="font-semibold text-gray-900 mb-2">Risk Analysis</h3>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">Average Risk Score:</span>
              <span className="font-semibold text-blue-600">{executiveSummary.average_risk_score}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Max Risk Score:</span>
              <span className="font-semibold text-red-600">{executiveSummary.max_risk_score}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Files Scanned:</span>
              <span className="font-semibold text-gray-900">{executiveSummary.files_scanned}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Scan Information */}
      <div className="bg-blue-50 p-4 rounded-lg mb-6">
        <h3 className="font-semibold text-gray-900 mb-2">Scan Information</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <span className="text-gray-600">Scan Date:</span>
            <span className="ml-2 font-semibold">
              {new Date(executiveSummary.scan_date).toLocaleDateString()}
            </span>
          </div>
          <div>
            <span className="text-gray-600">Duration:</span>
            <span className="ml-2 font-semibold">{executiveSummary.scan_duration}</span>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex space-x-4">
        {reportPath && (
          <button
            onClick={onDownload}
            className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 flex items-center"
          >
            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Download Report
          </button>
        )}
        
        <button
          className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700 flex items-center"
        >
          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          View Full Report
        </button>
      </div>

      {/* Recommendations */}
      <div className="mt-6 bg-yellow-50 p-4 rounded-lg">
        <h3 className="font-semibold text-gray-900 mb-2">💡 Recommendations</h3>
        <ul className="space-y-2 text-sm text-gray-700">
          {executiveSummary.high_severity > 0 && (
            <li>• <strong>Immediate Action Required:</strong> Address {executiveSummary.high_severity} high-severity findings to reduce security risk.</li>
          )}
          {executiveSummary.average_risk_score > 50 && (
            <li>• <strong>Risk Mitigation:</strong> Implement security controls to reduce the average risk score of {executiveSummary.average_risk_score}.</li>
          )}
          <li>• <strong>Continuous Monitoring:</strong> Set up automated scanning in your CI/CD pipeline to catch issues early.</li>
          <li>• <strong>Team Training:</strong> Provide security training to development teams on IaC best practices.</li>
        </ul>
      </div>
    </div>
  );
};

export default EnhancedReportViewer; 
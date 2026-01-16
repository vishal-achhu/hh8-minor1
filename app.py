import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Search, FileText, Cloud } from 'lucide-react';

const CloudMisconfigScanner = () => {
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [awsConfig, setAwsConfig] = useState({
    accessKey: '',
    secretKey: '',
    region: 'us-east-1'
  });

  // Simulated scan function (in real implementation, this would use AWS SDK)
  const performScan = async () => {
    setScanning(true);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 2500));
    
    // Simulated scan results
    const results = {
      timestamp: new Date().toISOString(),
      summary: {
        critical: 3,
        high: 5,
        medium: 8,
        low: 12,
        passed: 45
      },
      findings: [
        {
          id: 'S3-001',
          severity: 'critical',
          resource: 'my-company-backup',
          type: 'S3 Bucket',
          issue: 'Publicly Accessible Bucket',
          description: 'S3 bucket allows public read access to all users',
          recommendation: 'Remove "AllUsers" and "AuthenticatedUsers" from bucket policy',
          cisReference: 'CIS AWS 2.1.5',
          compliant: false
        },
        {
          id: 'S3-002',
          severity: 'critical',
          resource: 'data-lake-raw',
          type: 'S3 Bucket',
          issue: 'Bucket ACL Grants Public Access',
          description: 'Bucket ACL grants READ permission to "AllUsers"',
          recommendation: 'Update ACL to remove public access grants',
          cisReference: 'CIS AWS 2.1.5',
          compliant: false
        },
        {
          id: 'IAM-001',
          severity: 'critical',
          resource: 'AdminUser',
          type: 'IAM User',
          issue: 'Root Account Access Keys',
          description: 'Root account has active access keys',
          recommendation: 'Delete root access keys and use IAM users instead',
          cisReference: 'CIS AWS 1.4',
          compliant: false
        },
        {
          id: 'IAM-002',
          severity: 'high',
          resource: 'DevTeam',
          type: 'IAM Policy',
          issue: 'Overly Permissive Policy',
          description: 'Policy grants "s3:*" on all resources',
          recommendation: 'Apply principle of least privilege, restrict to specific buckets',
          cisReference: 'CIS AWS 1.16',
          compliant: false
        },
        {
          id: 'IAM-003',
          severity: 'high',
          resource: 'service-account',
          type: 'IAM User',
          issue: 'No MFA Enabled',
          description: 'IAM user with console access does not have MFA enabled',
          recommendation: 'Enable MFA for all users with console access',
          cisReference: 'CIS AWS 1.2',
          compliant: false
        },
        {
          id: 'S3-003',
          severity: 'high',
          resource: 'logs-archive',
          type: 'S3 Bucket',
          issue: 'Encryption Not Enabled',
          description: 'S3 bucket does not have default encryption enabled',
          recommendation: 'Enable default encryption with SSE-S3 or SSE-KMS',
          cisReference: 'CIS AWS 2.1.1',
          compliant: false
        },
        {
          id: 'S3-004',
          severity: 'medium',
          resource: 'app-assets',
          type: 'S3 Bucket',
          issue: 'Versioning Disabled',
          description: 'S3 bucket versioning is not enabled',
          recommendation: 'Enable versioning for data recovery and compliance',
          cisReference: 'CIS AWS 2.1.3',
          compliant: false
        },
        {
          id: 'IAM-004',
          severity: 'medium',
          resource: 'old-access-key',
          type: 'IAM Access Key',
          issue: 'Access Key Over 90 Days Old',
          description: 'Access key has not been rotated in 120 days',
          recommendation: 'Rotate access keys every 90 days',
          cisReference: 'CIS AWS 1.3',
          compliant: false
        }
      ]
    };
    
    setScanResults(results);
    setScanning(false);
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getSeverityIcon = (severity) => {
    if (severity === 'critical' || severity === 'high') {
      return <XCircle className="w-5 h-5" />;
    }
    return <AlertTriangle className="w-5 h-5" />;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-800">Cloud Misconfiguration Scanner</h1>
          </div>
          <p className="text-gray-600">AWS Security Audit Tool - Detects S3 and IAM Misconfigurations</p>
        </div>

        {/* Configuration Panel */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <Cloud className="w-5 h-5" />
            AWS Configuration
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Access Key ID
              </label>
              <input
                type="password"
                value={awsConfig.accessKey}
                onChange={(e) => setAwsConfig({...awsConfig, accessKey: e.target.value})}
                placeholder="AKIA..."
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Secret Access Key
              </label>
              <input
                type="password"
                value={awsConfig.secretKey}
                onChange={(e) => setAwsConfig({...awsConfig, secretKey: e.target.value})}
                placeholder="••••••••"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Region
              </label>
              <select
                value={awsConfig.region}
                onChange={(e) => setAwsConfig({...awsConfig, region: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU (Ireland)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
              </select>
            </div>
          </div>
          
          <button
            onClick={performScan}
            disabled={scanning}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-semibold py-3 px-6 rounded-md flex items-center justify-center gap-2 transition-colors"
          >
            <Search className="w-5 h-5" />
            {scanning ? 'Scanning...' : 'Start Security Scan'}
          </button>
          
          <p className="text-sm text-gray-500 mt-3">
            <strong>Demo Mode:</strong> This is a demonstration using simulated data. 
            In production, credentials would be used to scan actual AWS resources via Boto3.
          </p>
        </div>

        {/* Results */}
        {scanResults && (
          <>
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="text-red-600 text-2xl font-bold">{scanResults.summary.critical}</div>
                <div className="text-red-700 text-sm font-medium">Critical</div>
              </div>
              <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                <div className="text-orange-600 text-2xl font-bold">{scanResults.summary.high}</div>
                <div className="text-orange-700 text-sm font-medium">High</div>
              </div>
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <div className="text-yellow-600 text-2xl font-bold">{scanResults.summary.medium}</div>
                <div className="text-yellow-700 text-sm font-medium">Medium</div>
              </div>
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="text-blue-600 text-2xl font-bold">{scanResults.summary.low}</div>
                <div className="text-blue-700 text-sm font-medium">Low</div>
              </div>
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="text-green-600 text-2xl font-bold">{scanResults.summary.passed}</div>
                <div className="text-green-700 text-sm font-medium">Passed</div>
              </div>
            </div>

            {/* Findings List */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Security Findings
              </h2>
              
              <div className="space-y-4">
                {scanResults.findings.map((finding) => (
                  <div
                    key={finding.id}
                    className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold flex items-center gap-1 ${getSeverityColor(finding.severity)}`}>
                          {getSeverityIcon(finding.severity)}
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="text-sm font-mono text-gray-500">{finding.id}</span>
                      </div>
                      <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
                        {finding.cisReference}
                      </span>
                    </div>
                    
                    <h3 className="font-semibold text-gray-800 mb-1">{finding.issue}</h3>
                    <p className="text-sm text-gray-600 mb-2">
                      <strong>Resource:</strong> {finding.resource} ({finding.type})
                    </p>
                    <p className="text-sm text-gray-700 mb-3">{finding.description}</p>
                    
                    <div className="bg-blue-50 border border-blue-200 rounded p-3">
                      <p className="text-sm text-blue-900">
                        <strong className="flex items-center gap-1">
                          <CheckCircle className="w-4 h-4" />
                          Recommendation:
                        </strong>
                        {finding.recommendation}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* Info Panel */}
        {!scanResults && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
            <h3 className="font-semibold text-blue-900 mb-2">About This Scanner</h3>
            <p className="text-sm text-blue-800 mb-3">
              This tool audits AWS resources for common security misconfigurations including:
            </p>
            <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
              <li>S3 buckets with public access (AllUsers/AuthenticatedUsers permissions)</li>
              <li>S3 buckets without encryption or versioning</li>
              <li>IAM users without MFA enabled</li>
              <li>Overly permissive IAM policies</li>
              <li>Root account access keys</li>
              <li>Access keys older than 90 days</li>
            </ul>
            <p className="text-sm text-blue-800 mt-3">
              All checks are cross-referenced against CIS AWS Foundations Benchmark.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};


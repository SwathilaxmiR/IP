import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

// Create axios instance for direct API calls
const apiClient = axios.create({
  baseURL: API,
  headers: {
    'Content-Type': 'application/json',
  },
});

const getHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` })
  };
};

export const api = {
  // Repositories
  getRepositories: async () => {
    const response = await axios.get(`${API}/repositories`, { headers: getHeaders() });
    return response.data;
  },
  
  getRepository: async (id) => {
    const response = await axios.get(`${API}/repositories/${id}`, { headers: getHeaders() });
    return response.data;
  },
  
  createRepository: async (data) => {
    const response = await axios.post(`${API}/repositories`, data, { headers: getHeaders() });
    return response.data;
  },
  
  deleteRepository: async (id) => {
    await axios.delete(`${API}/repositories/${id}`, { headers: getHeaders() });
  },
  
  // Vulnerabilities
  getVulnerabilities: async (filters = {}) => {
    const params = new URLSearchParams(filters).toString();
    const response = await axios.get(`${API}/vulnerabilities?${params}`, { headers: getHeaders() });
    return response.data;
  },
  
  getVulnerability: async (id) => {
    const response = await axios.get(`${API}/vulnerabilities/${id}`, { headers: getHeaders() });
    return response.data;
  },
  
  updateVulnerabilityStatus: async (id, status) => {
    const response = await axios.patch(
      `${API}/vulnerabilities/${id}/status?new_status=${status}`,
      {},
      { headers: getHeaders() }
    );
    return response.data;
  },
  
  // Scans
  startScan: async (repositoryId, scanType = 'full') => {
    const response = await axios.post(
      `${API}/scan`,
      { repository_id: repositoryId, scan_type: scanType },
      { headers: getHeaders() }
    );
    return response.data;
  },
  
  getScanStatus: async (scanId) => {
    const response = await axios.get(`${API}/scan/${scanId}`, { headers: getHeaders() });
    return response.data;
  },
  
  // AI Patterns
  getAIPatterns: async (repositoryId) => {
    const params = repositoryId ? `?repository_id=${repositoryId}` : '';
    const response = await axios.get(`${API}/ai-patterns${params}`, { headers: getHeaders() });
    return response.data;
  },
  
  verifyAIPattern: async (patternId, isCorrect) => {
    const response = await axios.patch(
      `${API}/ai-patterns/${patternId}/verify?is_correct=${isCorrect}`,
      {},
      { headers: getHeaders() }
    );
    return response.data;
  },
  
  // Pull Requests
  getPullRequests: async (repositoryId) => {
    const params = repositoryId ? `?repository_id=${repositoryId}` : '';
    const response = await axios.get(`${API}/pull-requests${params}`, { headers: getHeaders() });
    return response.data;
  },
  
  triggerAutoFix: async (prId) => {
    const response = await axios.post(
      `${API}/pull-requests/${prId}/auto-fix`,
      {},
      { headers: getHeaders() }
    );
    return response.data;
  },
  
  // Activity
  getActivityLog: async (limit = 50) => {
    const response = await axios.get(`${API}/activity?limit=${limit}`, { headers: getHeaders() });
    return response.data;
  },
  
  // Dashboard
  getDashboardStats: async () => {
    const response = await axios.get(`${API}/dashboard/stats`, { headers: getHeaders() });
    return response.data;
  }
};
export default apiClient;

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import { Toaster } from './components/ui/sonner';
import LandingPage from './pages/LandingPage';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import Dashboard from './pages/Dashboard';
import Repositories from './pages/Repositories';
import RepositoryDetail from './pages/RepositoryDetail';
import VulnerabilityFeed from './pages/VulnerabilityFeed';
import AIKnowledgeBase from './pages/AIKnowledgeBase';
import ActivityLog from './pages/ActivityLog';
import Settings from './pages/Settings';
import './App.css';

const PrivateRoute = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  return isAuthenticated ? children : <Navigate to="/login" />;
};

const PublicRoute = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  return !isAuthenticated ? children : <Navigate to="/dashboard" />;
};

function App() {
  return (
    <div className="App grain-texture">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<PublicRoute><LandingPage /></PublicRoute>} />
          <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
          <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
          <Route path="/forgot-password" element={<PublicRoute><ForgotPassword /></PublicRoute>} />

          <Route path="/dashboard" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
          <Route path="/repositories" element={<PrivateRoute><Repositories /></PrivateRoute>} />
          <Route path="/repositories/:id" element={<PrivateRoute><RepositoryDetail /></PrivateRoute>} />
          <Route path="/vulnerabilities" element={<PrivateRoute><VulnerabilityFeed /></PrivateRoute>} />
          <Route path="/ai-knowledge" element={<PrivateRoute><AIKnowledgeBase /></PrivateRoute>} />
          <Route path="/activity" element={<PrivateRoute><ActivityLog /></PrivateRoute>} />
          <Route path="/settings" element={<PrivateRoute><Settings /></PrivateRoute>} />
        </Routes>
      </BrowserRouter>
      <Toaster position="top-right" richColors />
    </div>
  );
}

export default App;
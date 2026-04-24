import React, { useEffect, useState } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { CircularProgress, Box } from '@mui/material';

import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import SetupWizard from './pages/SetupWizard';
import Settings from './pages/Settings';
import SessionViewer from './pages/SessionViewer';
import Vulnerabilities from './pages/Vulnerabilities';
import ToolsStatus from './pages/ToolsStatus';
import LoginScreen from './pages/LoginScreen';
import AttackGraph from './pages/AttackGraph';
import IntelligenceDashboard from './pages/IntelligenceDashboard';
import About from './pages/About';
import { settingsApi } from './services/api';
import { useStore } from './store';

const AppRoutes: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { setSettings } = useStore();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const checkSetup = async () => {
      try {
        const s = await settingsApi.get();
        setSettings(s);
        if (s.setup_complete === 'false' && location.pathname !== '/setup') {
          navigate('/setup', { replace: true });
        }
      } catch {
        // If settings can't be loaded (e.g. first run), redirect to setup
        if (location.pathname !== '/setup') {
          navigate('/setup', { replace: true });
        }
      } finally {
        setChecking(false);
      }
    };
    checkSetup();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (checking) {
    return (
      <Box
        sx={{
          height: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#141414',
        }}
      >
        <CircularProgress color="primary" />
      </Box>
    );
  }

  return (
    <Routes>
      <Route path="/setup" element={<ErrorBoundary area="Setup"><SetupWizard /></ErrorBoundary>} />
      <Route
        path="/"
        element={
          <Layout>
            <ErrorBoundary area="Dashboard">
              <Dashboard />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/settings"
        element={
          <Layout>
            <ErrorBoundary area="Settings">
              <Settings />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/sessions/:id"
        element={
          <Layout>
            <ErrorBoundary area="Session Viewer">
              <SessionViewer />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/vulnerabilities"
        element={
          <Layout>
            <ErrorBoundary area="Vulnerabilities">
              <Vulnerabilities />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/tools"
        element={
          <Layout>
            <ErrorBoundary area="Tools">
              <ToolsStatus />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/intelligence"
        element={
          <Layout>
            <ErrorBoundary area="Intelligence">
              <IntelligenceDashboard />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route path="/sessions/:id/graph" element={<ErrorBoundary area="Attack Graph"><AttackGraph /></ErrorBoundary>} />
      <Route
        path="/about"
        element={
          <Layout>
            <ErrorBoundary area="About">
              <About />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

const App: React.FC = () => {
  const [apiKey, setApiKey] = useState<string | null>(() => localStorage.getItem('genesis_api_key'));

  const handleAuth = (key: string) => {
    localStorage.setItem('genesis_api_key', key);
    setApiKey(key);
  };

  if (apiKey === null) {
    return <LoginScreen onAuth={handleAuth} />;
  }

  return <AppRoutes />;
};

export default App;

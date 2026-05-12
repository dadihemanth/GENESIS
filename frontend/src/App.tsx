import React, { useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { CircularProgress, Box } from '@mui/material';

import Layout from './components/Layout';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import SetupWizard from './pages/SetupWizard';
import Settings from './pages/Settings';
import SessionViewer from './pages/SessionViewer';
import Sessions from './pages/Sessions';
import Vulnerabilities from './pages/Vulnerabilities';
import ToolsStatus from './pages/ToolsStatus';
import LoginScreen from './pages/LoginScreen';
import LoginPage from './pages/LoginPage';
import AttackGraph from './pages/AttackGraph';
import IntelligenceDashboard from './pages/IntelligenceDashboard';
import About from './pages/About';
import IntegrationsPage from './pages/IntegrationsPage';
import TenantsPage from './pages/TenantsPage';
import UsersPage from './pages/UsersPage';
import AgentChorusPage from './pages/AgentChorusPage';
import { settingsApi } from './services/api';
import { useStore } from './store';

const AppRoutes: React.FC<{ onAuthFailed: () => void }> = ({ onAuthFailed }) => {
  const { setSettings } = useStore();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const checkSetup = async () => {
      try {
        const s = await settingsApi.get();
        setSettings(s);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (
          msg.includes('Invalid or missing X-API-Key') ||
          msg.includes('Unauthorized') ||
          msg.includes('401')
        ) {
          onAuthFailed();
          return;
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
          backgroundColor: 'background.default',
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
        path="/sessions"
        element={
          <Layout>
            <ErrorBoundary area="Sessions">
              <Sessions />
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
      {/* v6.0 + v7.0 routes */}
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/integrations"
        element={
          <Layout>
            <ErrorBoundary area="Integrations">
              <IntegrationsPage />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/admin/tenants"
        element={
          <Layout>
            <ErrorBoundary area="Tenants">
              <TenantsPage />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/admin/users"
        element={
          <Layout>
            <ErrorBoundary area="Users">
              <UsersPage />
            </ErrorBoundary>
          </Layout>
        }
      />
      <Route
        path="/agents/chorus"
        element={
          <Layout>
            <ErrorBoundary area="Agent Chorus">
              <AgentChorusPage />
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

  const handleAuthFailed = () => {
    localStorage.removeItem('genesis_api_key');
    setApiKey(null);
  };

  if (apiKey === null) {
    return <LoginScreen onAuth={handleAuth} />;
  }

  return <AppRoutes onAuthFailed={handleAuthFailed} />;
};

export default App;

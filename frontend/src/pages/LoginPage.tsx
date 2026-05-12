import React, { useState } from 'react';
import {
  Box, Button, CircularProgress, Container, Paper,
  TextField, Typography, Alert, Divider,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import { authApi } from '../services/api';

interface LoginPageProps {
  onLogin?: (token: string) => void;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<'login' | 'register'>('login');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = mode === 'login'
        ? await authApi.login(email, password)
        : await authApi.register(email, password);
      localStorage.setItem('genesis_jwt', result.access_token);
      localStorage.setItem('genesis_user', JSON.stringify(result.user));
      onLogin?.(result.access_token);
      window.location.href = '/';
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0a0e1a 0%, #1a1f3a 100%)',
      }}
    >
      <Container maxWidth="xs">
        <Paper
          elevation={8}
          sx={{ p: 4, borderRadius: 2, background: 'rgba(255,255,255,0.05)', backdropFilter: 'blur(10px)' }}
        >
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 3 }}>
            <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 1 }} />
            <Typography variant="h5" fontWeight={700} color="text.primary">GENESIS</Typography>
            <Typography variant="caption" color="text.secondary">v7.0 · Tier 9</Typography>
          </Box>

          <Typography variant="h6" sx={{ mb: 3, textAlign: 'center' }}>
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </Typography>

          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth label="Email" type="email" variant="outlined" margin="normal"
              value={email} onChange={e => setEmail(e.target.value)} required autoFocus
            />
            <TextField
              fullWidth label="Password" type="password" variant="outlined" margin="normal"
              value={password} onChange={e => setPassword(e.target.value)} required
            />
            <Button
              type="submit" fullWidth variant="contained" size="large"
              sx={{ mt: 2 }} disabled={loading}
            >
              {loading ? <CircularProgress size={24} /> : mode === 'login' ? 'Sign in' : 'Create account'}
            </Button>
          </Box>

          <Divider sx={{ my: 2 }} />

          <Button
            fullWidth variant="text" size="small"
            onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
          >
            {mode === 'login' ? 'No account? Register' : 'Already have an account? Sign in'}
          </Button>
        </Paper>
      </Container>
    </Box>
  );
}

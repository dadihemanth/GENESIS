import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  Link,
} from '@mui/material';
import ShieldIcon from '@mui/icons-material/Shield';

interface Props {
  onAuth: (key: string) => void;
}

const LoginScreen: React.FC<Props> = ({ onAuth }) => {
  const [key, setKey] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!key.trim()) {
      setError('Please enter your API key');
      return;
    }
    onAuth(key.trim());
  };

  const handleSkip = () => {
    onAuth('');
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: '#fafbfd',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 3,
      }}
    >
      <Card sx={{ maxWidth: 420, width: '100%' }}>
        <CardContent sx={{ p: 4, textAlign: 'center' }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: '50%',
              backgroundColor: 'rgba(78,92,237,0.12)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              mx: 'auto',
              mb: 2.5,
            }}
          >
            <ShieldIcon sx={{ fontSize: 34, color: '#4e5ced' }} />
          </Box>
          <Typography variant="h5" sx={{ mb: 0.5, color: '#1a1f2e', fontWeight: 700 }}>
            GENESIS
          </Typography>
          <Typography variant="body2" sx={{ color: '#5a6478', mb: 3 }}>
            Enter the <code style={{ color: '#4e5ced', fontFamily: 'monospace' }}>API_KEY</code> from your{' '}
            <code style={{ color: '#4e5ced', fontFamily: 'monospace' }}>.env</code> file
          </Typography>
          <form onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="API Key"
              type="password"
              value={key}
              onChange={e => { setKey(e.target.value); setError(''); }}
              sx={{ mb: 2 }}
              autoFocus
              placeholder="Your API_KEY value"
              helperText="Default value: Gen@1234 (see API_KEY in your .env file)"
            />
            {error && (
              <Alert severity="error" sx={{ mb: 2, textAlign: 'left' }}>
                {error}
              </Alert>
            )}
            <Button type="submit" variant="contained" color="primary" fullWidth sx={{ mb: 1.5, py: 1.25 }}>
              Authenticate
            </Button>
          </form>
          <Link
            component="button"
            onClick={handleSkip}
            sx={{ fontSize: '0.8rem', color: '#8a93a6', cursor: 'pointer' }}
          >
            Skip — API key not configured
          </Link>
        </CardContent>
      </Card>
    </Box>
  );
};

export default LoginScreen;

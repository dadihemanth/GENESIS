import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  IconButton,
  Tooltip,
} from '@mui/material';
import ShieldIcon from '@mui/icons-material/Shield';
import SettingsIcon from '@mui/icons-material/Settings';
import LogoutIcon from '@mui/icons-material/Logout';
import { useNavigate } from 'react-router-dom';
import { useStore } from '../store';

const DRAWER_WIDTH = 240;

interface StatusDotProps {
  label: string;
  status: 'ok' | 'error' | 'unknown';
}

const StatusDot: React.FC<StatusDotProps> = ({ label, status }) => {
  const color =
    status === 'ok' ? '#4caf50' : status === 'error' ? '#f44336' : '#616161';
  return (
    <Tooltip title={`${label}: ${status}`}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'default' }}>
        <Box
          sx={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            backgroundColor: color,
          }}
        />
        <Typography variant="caption" sx={{ color: '#9e9e9e', fontSize: '0.68rem' }}>
          {label}
        </Typography>
      </Box>
    </Tooltip>
  );
};

const TopBar: React.FC = () => {
  const navigate = useNavigate();
  const health = useStore(s => s.health);

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        width: { sm: `calc(100% - ${DRAWER_WIDTH}px)` },
        ml: { sm: `${DRAWER_WIDTH}px` },
        backgroundColor: '#1a1a1a',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <Toolbar sx={{ minHeight: 64 }}>
        <Box sx={{ display: { xs: 'flex', sm: 'none' }, alignItems: 'center', mr: 2 }}>
          <ShieldIcon sx={{ color: '#86BC25', mr: 1 }} />
          <Typography variant="h6" sx={{ color: '#f0f0f0', fontWeight: 700, letterSpacing: '0.06em' }}>
            GENESIS
          </Typography>
        </Box>

        <Box sx={{ flexGrow: 1 }} />

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mr: 2 }}>
          <StatusDot label="API" status={health ? 'ok' : 'unknown'} />
          <StatusDot label="MCP" status={health ? health.mcp : 'unknown'} />
          <StatusDot
            label="DB"
            status={
              health
                ? health.postgres === 'ok' && health.mongodb === 'ok' && health.redis === 'ok'
                  ? 'ok'
                  : 'error'
                : 'unknown'
            }
          />
        </Box>

        <Tooltip title="Settings">
          <IconButton
            onClick={() => navigate('/settings')}
            sx={{ color: '#9e9e9e', '&:hover': { color: '#f0f0f0' } }}
          >
            <SettingsIcon />
          </IconButton>
        </Tooltip>

        <Tooltip title="Re-authenticate (change API key)">
          <IconButton
            onClick={() => {
              localStorage.removeItem('genesis_api_key');
              window.location.reload();
            }}
            sx={{ color: '#9e9e9e', '&:hover': { color: '#f44336' } }}
          >
            <LogoutIcon />
          </IconButton>
        </Tooltip>
      </Toolbar>
    </AppBar>
  );
};

export default TopBar;

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
import { tokens } from '../theme';

interface TopBarProps {
  sidebarWidth?: number;
}

interface StatusDotProps {
  label: string;
  status: 'ok' | 'error' | 'unknown';
}

const StatusDot: React.FC<StatusDotProps> = ({ label, status }) => {
  const color =
    status === 'ok'
      ? '#5bd38e'
      : status === 'error'
        ? '#ff7b7b'
        : 'rgba(255,255,255,0.45)';
  return (
    <Tooltip title={`${label}: ${status}`}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6, cursor: 'default' }}>
        <Box
          sx={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            backgroundColor: color,
            boxShadow:
              status === 'ok'
                ? '0 0 0 2px rgba(91,211,142,0.15)'
                : status === 'error'
                  ? '0 0 0 2px rgba(255,123,123,0.15)'
                  : 'none',
          }}
        />
        <Typography
          variant="caption"
          sx={{
            color: 'rgba(255,255,255,0.7)',
            fontSize: '0.68rem',
            letterSpacing: '0.4px',
          }}
        >
          {label}
        </Typography>
      </Box>
    </Tooltip>
  );
};

const TopBar: React.FC<TopBarProps> = ({ sidebarWidth = 240 }) => {
  const navigate = useNavigate();
  const health = useStore(s => s.health);

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        width: { sm: `calc(100% - ${sidebarWidth}px)` },
        ml: { sm: `${sidebarWidth}px` },
        backgroundImage: tokens.headerGradient,
        color: '#ffffff',
        transition: 'width 220ms ease, margin-left 220ms ease',
      }}
    >
      <Toolbar sx={{ minHeight: 64 }}>
        {/* Mobile-only brand lockup */}
        <Box sx={{ display: { xs: 'flex', sm: 'none' }, alignItems: 'center', mr: 2, ml: 4 }}>
          <ShieldIcon sx={{ color: '#ffffff', mr: 1 }} />
          <Typography
            variant="h6"
            sx={{
              color: '#ffffff',
              fontWeight: 700,
              letterSpacing: '-0.2px',
            }}
          >
            GENESIS
          </Typography>
        </Box>

        <Box sx={{ flexGrow: 1 }} />

        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 2,
            mr: 2,
            px: 1.5,
            py: 0.75,
            borderRadius: 99,
            background: 'rgba(255,255,255,0.08)',
            border: '1px solid rgba(255,255,255,0.12)',
          }}
        >
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
            sx={{
              color: 'rgba(255,255,255,0.8)',
              '&:hover': {
                color: '#ffffff',
                backgroundColor: 'rgba(255,255,255,0.08)',
              },
            }}
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
            sx={{
              color: 'rgba(255,255,255,0.8)',
              '&:hover': {
                color: '#ff9b9b',
                backgroundColor: 'rgba(255,123,123,0.12)',
              },
            }}
          >
            <LogoutIcon />
          </IconButton>
        </Tooltip>
      </Toolbar>
    </AppBar>
  );
};

export default TopBar;

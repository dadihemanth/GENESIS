import React from 'react';
import {
  Box,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
  Divider,
  Chip,
} from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import BugReportIcon from '@mui/icons-material/BugReport';
import BuildIcon from '@mui/icons-material/Build';
import SettingsIcon from '@mui/icons-material/Settings';
import WizardIcon from '@mui/icons-material/AutoFixHigh';
import ShieldIcon from '@mui/icons-material/Shield';
import GitHubIcon from '@mui/icons-material/GitHub';
import PsychologyIcon from '@mui/icons-material/Psychology';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { useNavigate, useLocation } from 'react-router-dom';
import { useStore } from '../store';

export const DRAWER_WIDTH = 240;

const navItems = [
  { label: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { label: 'Vulnerabilities', icon: <BugReportIcon />, path: '/vulnerabilities' },
  { label: 'Intelligence', icon: <PsychologyIcon />, path: '/intelligence' },
  { label: 'Tools', icon: <BuildIcon />, path: '/tools' },
  { label: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  { label: 'About', icon: <InfoOutlinedIcon />, path: '/about' },
];

interface SidebarProps {
  mobileOpen: boolean;
  onClose: () => void;
}

const SidebarContent: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const settings = useStore(s => s.settings);
  const setupIncomplete = settings?.setup_complete === 'false';

  return (
    <Box
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: '#1a1a1a',
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          px: 2.5,
          py: 2.5,
          borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}
      >
        <ShieldIcon sx={{ color: '#86BC25', fontSize: 26 }} />
        <Box>
          <Typography
            variant="h6"
            sx={{
              color: '#f0f0f0',
              fontWeight: 700,
              fontSize: '1rem',
              letterSpacing: '0.04em',
              lineHeight: 1.2,
            }}
          >
            GENESIS
          </Typography>
          <Typography variant="caption" sx={{ color: '#616161', fontSize: '0.65rem' }}>
            Security Intelligence
          </Typography>
        </Box>
      </Box>

      <List sx={{ px: 1.5, pt: 1.5, flexGrow: 1 }}>
        {navItems.map(item => {
          const active = location.pathname === item.path;
          return (
            <ListItem key={item.path} disablePadding sx={{ mb: 0.5 }}>
              <ListItemButton
                onClick={() => navigate(item.path)}
                sx={{
                  borderRadius: 1.5,
                  backgroundColor: active ? 'rgba(134,188,37,0.10)' : 'transparent',
                  '&:hover': { backgroundColor: active ? 'rgba(134,188,37,0.12)' : 'rgba(255,255,255,0.04)' },
                  py: 1,
                  px: 1.5,
                }}
              >
                <ListItemIcon
                  sx={{
                    minWidth: 36,
                    color: active ? '#86BC25' : '#616161',
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{
                    fontSize: '0.875rem',
                    fontWeight: active ? 600 : 400,
                    color: active ? '#f0f0f0' : '#9e9e9e',
                  }}
                />
                {active && (
                  <Box
                    sx={{
                      width: 3,
                      height: 18,
                      backgroundColor: '#86BC25',
                      borderRadius: 2,
                      ml: 1,
                    }}
                  />
                )}
              </ListItemButton>
            </ListItem>
          );
        })}

        {setupIncomplete && (
          <>
            <Divider sx={{ my: 1.5, borderColor: 'rgba(255,255,255,0.06)' }} />
            <ListItem disablePadding>
              <ListItemButton
                onClick={() => navigate('/setup')}
                sx={{
                  borderRadius: 1.5,
                  border: '1px solid rgba(255,152,0,0.3)',
                  '&:hover': { backgroundColor: 'rgba(255,152,0,0.06)' },
                }}
              >
                <ListItemIcon sx={{ minWidth: 36, color: '#ff9800' }}>
                  <WizardIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Setup"
                  primaryTypographyProps={{ fontSize: '0.875rem', color: '#ff9800' }}
                />
                <Chip label="!" size="small" sx={{ backgroundColor: '#ff9800', color: '#000', fontSize: '0.65rem', height: 18 }} />
              </ListItemButton>
            </ListItem>
          </>
        )}
      </List>

      <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />
      <Box sx={{ p: 2 }}>
        <Box
          component="a"
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1,
            color: '#616161',
            textDecoration: 'none',
            '&:hover': { color: '#9e9e9e' },
            mb: 1,
          }}
        >
          <GitHubIcon fontSize="small" />
          <Typography variant="caption">GitHub</Typography>
        </Box>
        <Typography variant="caption" sx={{ color: '#424242', fontSize: '0.65rem' }}>
          v1.0.0
        </Typography>
      </Box>
    </Box>
  );
};

const Sidebar: React.FC<SidebarProps> = ({ mobileOpen, onClose }) => {
  const drawerSx = {
    '& .MuiDrawer-paper': {
      width: DRAWER_WIDTH,
      boxSizing: 'border-box' as const,
      backgroundColor: '#1a1a1a',
      border: 'none',
      borderRight: '1px solid rgba(255,255,255,0.06)',
    },
  };

  return (
    <>
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onClose}
        ModalProps={{ keepMounted: true }}
        sx={{ display: { xs: 'block', sm: 'none' }, ...drawerSx }}
      >
        <SidebarContent />
      </Drawer>

      <Drawer
        variant="permanent"
        sx={{ display: { xs: 'none', sm: 'block' }, ...drawerSx }}
        open
      >
        <SidebarContent />
      </Drawer>
    </>
  );
};

export default Sidebar;

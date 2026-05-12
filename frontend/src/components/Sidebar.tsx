import React from 'react';
import {
  Box,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Tooltip,
  Typography,
  Divider,
  Chip,
} from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import HistoryIcon from '@mui/icons-material/History';
import BugReportIcon from '@mui/icons-material/BugReport';
import BuildIcon from '@mui/icons-material/Build';
import SettingsIcon from '@mui/icons-material/Settings';
import WizardIcon from '@mui/icons-material/AutoFixHigh';
import PsychologyIcon from '@mui/icons-material/Psychology';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';
import GroupsIcon from '@mui/icons-material/Groups';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import { useNavigate, useLocation } from 'react-router-dom';
import { useStore } from '../store';
import { tokens } from '../theme';

export const DRAWER_WIDTH = 240;
export const DRAWER_WIDTH_COLLAPSED = 64;

const navItems = [
  { label: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { label: 'Sessions', icon: <HistoryIcon />, path: '/sessions' },
  { label: 'Vulnerabilities', icon: <BugReportIcon />, path: '/vulnerabilities' },
  { label: 'Intelligence', icon: <PsychologyIcon />, path: '/intelligence' },
  { label: 'Tools', icon: <BuildIcon />, path: '/tools' },
  { label: 'Integrations', icon: <IntegrationInstructionsIcon />, path: '/integrations' },
  { label: 'Users', icon: <GroupsIcon />, path: '/admin/users' },
  { label: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  { label: 'About', icon: <InfoOutlinedIcon />, path: '/about' },
];

interface SidebarProps {
  mobileOpen: boolean;
  onClose: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

interface SidebarContentProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
}

const SidebarContent: React.FC<SidebarContentProps> = ({ collapsed, onToggleCollapse }) => {
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
        backgroundColor: tokens.panel,
      }}
    >
      {/* Sidebar header — dark gradient bar matching the manual's top banner */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: collapsed ? 0 : 1.5,
          justifyContent: collapsed ? 'center' : 'flex-start',
          px: collapsed ? 1 : 2.5,
          py: 2.25,
          backgroundImage: tokens.headerGradient,
          color: '#ffffff',
          position: 'relative',
        }}
      >
        {collapsed ? (
          <Typography sx={{ color: '#ffffff', fontWeight: 700, fontSize: '1.1rem', lineHeight: 1 }}>
            G
          </Typography>
        ) : (
          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Typography
              variant="h6"
              sx={{
                color: '#ffffff',
                fontWeight: 700,
                fontSize: '1.25rem',
                letterSpacing: '-0.3px',
                lineHeight: 1.2,
              }}
            >
              GENESIS
            </Typography>
          </Box>
        )}
        <Tooltip title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} placement="right">
          <IconButton
            onClick={onToggleCollapse}
            size="small"
            sx={{
              color: '#ffffff',
              opacity: 0.85,
              backgroundColor: 'rgba(255,255,255,0.10)',
              '&:hover': { backgroundColor: 'rgba(255,255,255,0.20)', opacity: 1 },
              p: 0.5,
              ...(collapsed && { position: 'absolute', right: -12, top: '50%', transform: 'translateY(-50%)',
                                  backgroundColor: tokens.panel, color: tokens.ink, border: `1px solid ${tokens.rule}`,
                                  '&:hover': { backgroundColor: tokens.panel } }),
            }}
          >
            {collapsed ? <ChevronRightIcon sx={{ fontSize: 18 }} /> : <ChevronLeftIcon sx={{ fontSize: 18 }} />}
          </IconButton>
        </Tooltip>
      </Box>

      <List sx={{ px: collapsed ? 0.5 : 1.5, pt: 1.5, flexGrow: 1, overflowY: 'auto', minHeight: 0 }}>
        {navItems.map(item => {
          const active = location.pathname === item.path;
          const button = (
            <ListItemButton
              onClick={() => navigate(item.path)}
              selected={active}
              sx={{
                py: 1,
                px: collapsed ? 1 : 1.5,
                justifyContent: collapsed ? 'center' : 'flex-start',
                minHeight: 40,
              }}
            >
              <ListItemIcon sx={{ minWidth: collapsed ? 0 : 36, justifyContent: 'center' }}>
                {item.icon}
              </ListItemIcon>
              {!collapsed && (
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{
                    fontSize: '0.875rem',
                    fontWeight: active ? 600 : 500,
                    color: active ? tokens.ink : '#3a4256',
                  }}
                />
              )}
              {!collapsed && active && (
                <Box
                  sx={{
                    width: 3,
                    height: 18,
                    backgroundColor: tokens.accent,
                    borderRadius: 2,
                    ml: 1,
                  }}
                />
              )}
            </ListItemButton>
          );
          return (
            <ListItem key={item.path} disablePadding sx={{ mb: 0.5 }}>
              {collapsed ? (
                <Tooltip title={item.label} placement="right">{button}</Tooltip>
              ) : button}
            </ListItem>
          );
        })}

        {setupIncomplete && (
          <>
            <Divider sx={{ my: 1.5 }} />
            <ListItem disablePadding>
              {(() => {
                const setupBtn = (
                  <ListItemButton
                    onClick={() => navigate('/setup')}
                    sx={{
                      border: `1px solid ${tokens.warn}`,
                      backgroundColor: '#fdf5ec',
                      px: collapsed ? 1 : 1.5,
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      '&:hover': { backgroundColor: '#fbeed9' },
                    }}
                  >
                    <ListItemIcon sx={{ color: tokens.warn, minWidth: collapsed ? 0 : 36, justifyContent: 'center' }}>
                      <WizardIcon />
                    </ListItemIcon>
                    {!collapsed && (
                      <>
                        <ListItemText
                          primary="Setup"
                          primaryTypographyProps={{
                            fontSize: '0.875rem',
                            fontWeight: 600,
                            color: tokens.warn,
                          }}
                        />
                        <Chip
                          label="!"
                          size="small"
                          sx={{
                            backgroundColor: tokens.warn,
                            color: '#ffffff',
                            fontSize: '0.65rem',
                            height: 18,
                            minWidth: 18,
                          }}
                        />
                      </>
                    )}
                  </ListItemButton>
                );
                return collapsed
                  ? <Tooltip title="Setup required" placement="right">{setupBtn}</Tooltip>
                  : setupBtn;
              })()}
            </ListItem>
          </>
        )}
      </List>

      <Divider />
      <Box sx={{ p: collapsed ? 1 : 2, textAlign: 'center', flexShrink: 0 }}>
        {!collapsed && (
          <Typography
            variant="caption"
            sx={{ fontSize: '0.65rem', display: 'block', mb: 0.4, color: tokens.muted }}
          >
            Contributor :{' '}
            <Tooltip title="hemanthhemanth6@deloitte.com" arrow placement="top">
              <Box
                component="span"
                sx={{ color: '#4e5ced', fontWeight: 700, cursor: 'help' }}
              >
                Hemanth Dadi
              </Box>
            </Tooltip>
          </Typography>
        )}
        <Typography
          variant="caption"
          sx={{
            color: tokens.muted,
            fontSize: '0.65rem',
            display: 'block',
            fontFamily: 'monospace',
            fontWeight: 600,
          }}
        >
          {collapsed ? 'v7' : 'v7.0 · Tier 9'}
        </Typography>
      </Box>
    </Box>
  );
};

const Sidebar: React.FC<SidebarProps> = ({ mobileOpen, onClose, collapsed, onToggleCollapse }) => {
  const width = collapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH;
  const drawerSx = {
    '& .MuiDrawer-paper': {
      width,
      boxSizing: 'border-box' as const,
      backgroundColor: tokens.panel,
      border: 'none',
      borderRight: `1px solid ${tokens.rule}`,
      overflowX: 'hidden' as const,
      transition: 'width 220ms ease',
    },
  };

  return (
    <>
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onClose}
        ModalProps={{ keepMounted: true }}
        sx={{ display: { xs: 'block', sm: 'none' },
              '& .MuiDrawer-paper': { ...drawerSx['& .MuiDrawer-paper'], width: DRAWER_WIDTH } }}
      >
        <SidebarContent collapsed={false} onToggleCollapse={onToggleCollapse} />
      </Drawer>

      <Drawer
        variant="permanent"
        sx={{ display: { xs: 'none', sm: 'block' }, ...drawerSx }}
        open
      >
        <SidebarContent collapsed={collapsed} onToggleCollapse={onToggleCollapse} />
      </Drawer>
    </>
  );
};

export default Sidebar;

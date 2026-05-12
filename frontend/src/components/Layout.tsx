import React, { useState, useEffect } from 'react';
import { Box, IconButton, Toolbar } from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import TopBar from './TopBar';
import Sidebar, { DRAWER_WIDTH, DRAWER_WIDTH_COLLAPSED } from './Sidebar';
import { healthApi } from '../services/api';
import { useStore } from '../store';

interface LayoutProps {
  children: React.ReactNode;
}

const COLLAPSED_KEY = 'genesis_sidebar_collapsed';

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  // Persist the collapsed state across refreshes — operators settle into one
  // mode and don't want to re-toggle on every page load.
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try { return localStorage.getItem(COLLAPSED_KEY) === '1'; } catch { return false; }
  });
  const { setHealth } = useStore();

  useEffect(() => {
    try { localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0'); } catch { /* ignore */ }
  }, [collapsed]);

  useEffect(() => {
    const poll = () => healthApi.check().then(setHealth).catch(() => {});
    poll();
    const id = setInterval(poll, 30000);
    return () => clearInterval(id);
  }, [setHealth]);

  const sidebarWidth = collapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH;

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', backgroundColor: 'background.default' }}>
      <TopBar sidebarWidth={sidebarWidth} />
      <Sidebar
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(v => !v)}
      />

      {/* Mobile menu button — overlaid on TopBar */}
      <Box
        sx={{
          display: { xs: 'block', sm: 'none' },
          position: 'fixed',
          top: 12,
          left: 12,
          zIndex: 1300,
        }}
      >
        <IconButton
          onClick={() => setMobileOpen(true)}
          sx={{ color: '#ffffff' }}
        >
          <MenuIcon />
        </IconButton>
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          width: { sm: `calc(100% - ${sidebarWidth}px)` },
          ml: { sm: `${sidebarWidth}px` },
          display: 'flex',
          flexDirection: 'column',
          transition: 'width 220ms ease, margin-left 220ms ease',
        }}
      >
        <Toolbar sx={{ minHeight: 64 }} />
        <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
          {children}
        </Box>
      </Box>
    </Box>
  );
};

export default Layout;

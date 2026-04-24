import React, { useState, useEffect } from 'react';
import { Box, IconButton, Toolbar } from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import TopBar from './TopBar';
import Sidebar, { DRAWER_WIDTH } from './Sidebar';
import { healthApi } from '../services/api';
import { useStore } from '../store';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { setHealth } = useStore();

  useEffect(() => {
    const poll = () => healthApi.check().then(setHealth).catch(() => {});
    poll();
    const id = setInterval(poll, 30000);
    return () => clearInterval(id);
  }, [setHealth]);

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', backgroundColor: '#141414' }}>
      <TopBar />
      <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />

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
          color="inherit"
          onClick={() => setMobileOpen(true)}
          sx={{ color: '#9e9e9e' }}
        >
          <MenuIcon />
        </IconButton>
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          width: { sm: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { sm: `${DRAWER_WIDTH}px` },
          display: 'flex',
          flexDirection: 'column',
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

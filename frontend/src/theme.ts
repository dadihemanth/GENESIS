import { createTheme } from '@mui/material/styles';

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#86BC25', dark: '#6da120', light: '#9ed12e', contrastText: '#ffffff' },
    secondary: { main: '#616161' },
    background: { default: '#141414', paper: '#1e1e1e' },
    success: { main: '#4caf50' },
    warning: { main: '#ff9800' },
    error: { main: '#f44336' },
    text: { primary: '#f0f0f0', secondary: '#9e9e9e' },
    divider: 'rgba(255,255,255,0.08)',
  },
  typography: {
    fontFamily: '"Inter", "Segoe UI", system-ui, sans-serif',
    h4: { fontWeight: 700, letterSpacing: '-0.01em' },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
  },
  shape: { borderRadius: 8 },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: '1px solid rgba(255,255,255,0.06)',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: '1px solid rgba(255,255,255,0.06)',
          transition: 'border-color 0.15s ease',
          '&:hover': {
            borderColor: 'rgba(134,188,37,0.25)',
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        containedPrimary: {
          fontWeight: 600,
          boxShadow: 'none',
          '&:hover': { boxShadow: 'none', backgroundColor: '#6da120' },
        },
        outlinedPrimary: {
          borderColor: 'rgba(134,188,37,0.4)',
          '&:hover': { borderColor: '#86BC25', backgroundColor: 'rgba(134,188,37,0.06)' },
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { fontWeight: 500 },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottomColor: 'rgba(255,255,255,0.05)',
        },
        head: {
          color: '#9e9e9e',
          fontWeight: 600,
          fontSize: '0.75rem',
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        notchedOutline: { borderColor: 'rgba(255,255,255,0.12)' },
        root: {
          '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.25)' },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#86BC25' },
        },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          '&.Mui-focused': { color: '#86BC25' },
        },
      },
    },
    MuiSlider: {
      styleOverrides: {
        thumb: { '&:hover': { boxShadow: '0 0 0 8px rgba(134,188,37,0.16)' } },
      },
    },
  },
});

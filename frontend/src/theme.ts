import { createTheme } from '@mui/material/styles';

// Theme tokens mirror the ones in GENESIS_Manual.html:
//   --ink:#1a1f2e   --muted:#5a6478   --faint:#e8ecf4
//   --bg:#fafbfd    --panel:#ffffff   --accent:#4e5ced
//   --ok:#137a4e    --warn:#b5581a    --danger:#b53030
//   --rule:#dfe3ec  --code-bg:#f1f3f9 --header-grad: 135deg, #1e2539 → #384069
//
// Shadow used by cards and panels in the manual:
const cardShadow = '0 1px 3px rgba(0,0,0,0.04), 0 4px 14px rgba(0,0,0,0.06)';
const softShadow = '0 1px 2px rgba(0,0,0,0.03), 0 2px 4px rgba(0,0,0,0.04)';

export const tokens = {
  ink: '#1a1f2e',
  muted: '#5a6478',
  faint: '#f1f5f9',
  bg: '#f8fafc',
  panel: '#ffffff',
  accent: '#4e5ced',
  accentFaint: '#e7eafc',
  ok: '#137a4e',
  warn: '#b5581a',
  danger: '#b53030',
  rule: '#e2e8f0',
  codeBg: '#f1f3f9',
  headerGradient: 'linear-gradient(160deg,#0f172a,#1e293b)',
  cardShadow,
  softShadow,
} as const;

export const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: tokens.accent,
      dark: '#3f4dd1',
      light: '#7481f0',
      contrastText: '#ffffff',
    },
    secondary: {
      main: tokens.muted,
    },
    background: {
      default: tokens.bg,
      paper: tokens.panel,
    },
    success: { main: tokens.ok },
    warning: { main: tokens.warn },
    error:   { main: tokens.danger },
    text: {
      primary: tokens.ink,
      secondary: tokens.muted,
    },
    divider: tokens.rule,
  },
  typography: {
    // Matches the manual's system font stack exactly.
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", system-ui, sans-serif',
    h4: { fontWeight: 700, letterSpacing: '-0.4px', color: tokens.ink },
    h5: { fontWeight: 700, letterSpacing: '-0.3px', color: tokens.ink },
    h6: { fontWeight: 600, letterSpacing: '-0.2px', color: tokens.ink },
    subtitle1: { color: tokens.ink, fontWeight: 600 },
    subtitle2: { color: tokens.muted, fontWeight: 500 },
    body1: { color: '#2a3045' },
    body2: { color: '#2a3045' },
    caption: { color: tokens.muted },
    overline: {
      color: tokens.muted,
      letterSpacing: '0.7px',
      fontWeight: 600,
      fontSize: '11px',
    },
  },
  shape: { borderRadius: 12 },
  shadows: [
    'none',
    softShadow,
    softShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
    cardShadow,
  ],
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: tokens.bg,
          color: tokens.ink,
        },
        // Matches the manual's <code> / <pre> styling.
        code: {
          background: tokens.codeBg,
          color: '#2a3045',
          padding: '1px 6px',
          borderRadius: 4,
          font: '13px/1.4 "SF Mono","Consolas",monospace',
        },
        pre: {
          background: tokens.codeBg,
          padding: '14px 16px',
          borderRadius: 10,
          overflowX: 'auto',
          font: '13px/1.5 "SF Mono","Consolas",monospace',
          color: tokens.ink,
        },
      },
    },
    MuiPaper: {
      defaultProps: { elevation: 0 },
      styleOverrides: {
        root: {
          backgroundColor: tokens.panel,
          backgroundImage: 'none',
          border: '1px solid rgba(30,41,60,0.08)',
          boxShadow: softShadow,
        },
      },
    },
    MuiCard: {
      defaultProps: { elevation: 0 },
      styleOverrides: {
        root: {
          backgroundColor: tokens.panel,
          border: '1px solid rgba(30,41,60,0.08)',
          boxShadow: cardShadow,
          transition: 'border-color .15s ease, box-shadow .15s ease',
          '&:hover': {
            borderColor: 'rgba(78,92,237,0.25)',
          },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: tokens.headerGradient,
          backgroundColor: '#0f172a',
          color: '#ffffff',
          boxShadow: 'none',
          borderBottom: 'none',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: tokens.panel,
          borderRight: '1px solid rgba(30,41,60,0.08)',
          boxShadow: 'none',
        },
      },
    },
    MuiToolbar: {
      styleOverrides: {
        root: {
          minHeight: 64,
        },
      },
    },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          borderRadius: 8,
        },
        containedPrimary: {
          backgroundColor: tokens.accent,
          '&:hover': { backgroundColor: '#3f4dd1' },
        },
        outlinedPrimary: {
          borderColor: 'rgba(78, 92, 237, 0.45)',
          color: tokens.accent,
          '&:hover': {
            borderColor: tokens.accent,
            backgroundColor: 'rgba(78, 92, 237, 0.06)',
          },
        },
        text: {
          color: tokens.ink,
          '&:hover': { backgroundColor: tokens.faint },
        },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          color: tokens.muted,
          '&:hover': {
            color: tokens.ink,
            backgroundColor: tokens.faint,
          },
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          color: tokens.muted,
          minHeight: 44,
          '&.Mui-selected': {
            color: tokens.accent,
          },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          backgroundColor: tokens.accent,
          height: 2.5,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 600,
          borderRadius: 99,
        },
        colorPrimary: {
          backgroundColor: tokens.accentFaint,
          color: tokens.accent,
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottomColor: tokens.rule,
          color: '#2a3045',
        },
        head: {
          backgroundColor: '#f8fafc',
          color: tokens.muted,
          fontSize: '12px',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.7px',
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 6,
          '&:hover': { backgroundColor: tokens.faint },
          '&.Mui-selected, &.Mui-selected:hover': {
            backgroundColor: tokens.accentFaint,
            color: tokens.accent,
            '& .MuiListItemIcon-root': { color: tokens.accent },
            '& .MuiListItemText-primary': { color: tokens.ink, fontWeight: 600 },
          },
        },
      },
    },
    MuiListItemIcon: {
      styleOverrides: {
        root: { color: tokens.muted, minWidth: 36 },
      },
    },
    MuiDivider: {
      styleOverrides: {
        root: { borderColor: tokens.rule },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          backgroundColor: tokens.panel,
          borderRadius: 8,
          '& .MuiOutlinedInput-notchedOutline': { borderColor: tokens.rule },
          '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#c3cad7' },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderColor: tokens.accent,
            borderWidth: 1.5,
          },
        },
        input: { color: tokens.ink },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          color: tokens.muted,
          '&.Mui-focused': { color: tokens.accent },
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 10,
          border: `1px solid ${tokens.rule}`,
          borderLeftWidth: 3,
        },
        standardInfo: {
          backgroundColor: '#f6f8fc',
          borderLeftColor: tokens.accent,
          color: tokens.ink,
        },
        standardSuccess: {
          backgroundColor: '#edf7f1',
          borderLeftColor: tokens.ok,
          color: tokens.ink,
        },
        standardWarning: {
          backgroundColor: '#fdf5ec',
          borderLeftColor: tokens.warn,
          color: tokens.ink,
        },
        standardError: {
          backgroundColor: '#fbecec',
          borderLeftColor: tokens.danger,
          color: tokens.ink,
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          backgroundColor: tokens.ink,
          color: '#ffffff',
          fontSize: 12,
          padding: '6px 10px',
          borderRadius: 6,
        },
        arrow: { color: tokens.ink },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          height: 6,
          borderRadius: 3,
          backgroundColor: tokens.faint,
        },
        bar: { backgroundColor: tokens.accent },
      },
    },
    MuiSlider: {
      styleOverrides: {
        thumb: {
          '&:hover': { boxShadow: '0 0 0 8px rgba(78,92,237,0.12)' },
        },
      },
    },
  },
});

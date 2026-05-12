import React from 'react';
import { Alert, AlertTitle, Box, Button, Typography } from '@mui/material';

interface Props {
  children: React.ReactNode;
  /** Optional label shown in the fallback UI so operators know which area crashed. */
  area?: string;
}

interface State {
  error: Error | null;
  info: React.ErrorInfo | null;
}

/**
 * Catches render-time errors in the subtree and shows a visible fallback
 * instead of silently blanking the page.
 *
 * React swallows render errors above the nearest error boundary — without
 * one, a single runtime crash in any component unmounts the whole tree and
 * the user sees nothing. This boundary captures the error, preserves the
 * chrome (so users can navigate away), and shows the message + stack.
 */
export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { error: null, info: null };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    // Surface to the console so we still get a stack trace in DevTools.
    // eslint-disable-next-line no-console
    console.error(`[ErrorBoundary${this.props.area ? ` · ${this.props.area}` : ''}]`, error, info);
    this.setState({ info });
  }

  reset = (): void => {
    this.setState({ error: null, info: null });
  };

  reload = (): void => {
    window.location.reload();
  };

  render(): React.ReactNode {
    if (!this.state.error) return this.props.children;

    const stack = this.state.info?.componentStack ?? '';
    return (
      <Box sx={{ p: 3, maxWidth: 960, mx: 'auto' }}>
        <Alert severity="error" variant="standard">
          <AlertTitle sx={{ fontWeight: 700 }}>
            Something broke in the UI{this.props.area ? ` (${this.props.area})` : ''}
          </AlertTitle>
          <Typography sx={{ fontSize: '0.85rem', mb: 1 }}>
            {this.state.error.message || String(this.state.error)}
          </Typography>
          {stack && (
            <Box
              component="pre"
              sx={{
                m: 0,
                p: 1.5,
                backgroundColor: '#f1f3f9',
                color: '#2a3045',
                fontFamily: '"SF Mono","Consolas",monospace',
                fontSize: '0.72rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                maxHeight: 260,
                overflow: 'auto',
                borderRadius: 1,
                border: '1px solid #dfe3ec',
              }}
            >
              {stack.trim()}
            </Box>
          )}
          <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
            <Button size="small" variant="outlined" color="error" onClick={this.reset}>
              Try Again
            </Button>
            <Button size="small" variant="contained" color="primary" onClick={this.reload}>
              Reload Page
            </Button>
          </Box>
        </Alert>
      </Box>
    );
  }
}

export default ErrorBoundary;

import React, { useEffect, useState } from 'react';
import {
  Box, Button, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle, Paper, Table, TableBody, TableCell, TableHead, TableRow,
  TextField, Typography, Alert,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import { authApi } from '../services/api';
import type { Tenant } from '../types';

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadTenants = async () => {
    try {
      const data = await authApi.listTenants();
      setTenants(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load tenants');
    }
    setLoading(false);
  };

  useEffect(() => { loadTenants(); }, []);

  const handleCreate = async () => {
    setSaving(true);
    try {
      await authApi.createTenant(name, slug || name.toLowerCase().replace(/\s+/g, '-'));
      setDialogOpen(false);
      setName('');
      setSlug('');
      await loadTenants();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create tenant');
    }
    setSaving(false);
  };

  if (loading) return <Box sx={{ p: 4, display: 'flex', justifyContent: 'center' }}><CircularProgress /></Box>;

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>Tenants</Typography>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setDialogOpen(true)}>New Tenant</Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}

      <Paper variant="outlined">
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Slug</TableCell>
              <TableCell>Created</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {tenants.length === 0 && (
              <TableRow>
                <TableCell colSpan={3}>
                  <Typography color="text.secondary" align="center">No tenants found</Typography>
                </TableCell>
              </TableRow>
            )}
            {tenants.map(t => (
              <TableRow key={t.id} hover>
                <TableCell>{t.name}</TableCell>
                <TableCell><code>{t.slug}</code></TableCell>
                <TableCell>{new Date(t.created_at).toLocaleDateString()}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)}>
        <DialogTitle>New Tenant</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth label="Name" value={name}
            onChange={e => setName(e.target.value)}
            sx={{ mt: 1, mb: 2 }} autoFocus
          />
          <TextField
            fullWidth label="Slug (optional)" value={slug}
            onChange={e => setSlug(e.target.value)}
            helperText="Auto-generated from name if empty"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} variant="contained" disabled={saving || !name}>
            {saving ? <CircularProgress size={20} /> : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

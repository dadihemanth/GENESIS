import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  IconButton,
  LinearProgress,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Tooltip,
  Typography,
} from '@mui/material';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import FactCheckIcon from '@mui/icons-material/FactCheck';
import RefreshIcon from '@mui/icons-material/Refresh';
import ScienceIcon from '@mui/icons-material/Science';
import VerifiedIcon from '@mui/icons-material/Verified';
import { validatedApi } from '../services/api';
import type {
  BenchmarkReport,
  CandidateFinding,
  ConfirmFindingsResult,
  FindingCluster,
  ProofRun,
  TargetSurfaceGraph,
  ValidationProofJob,
  ValidationVerdict,
} from '../types';

interface Props {
  sessionId: string;
  sessionStatus?: string;
}

interface PanelData {
  candidates: CandidateFinding[];
  verdicts: ValidationVerdict[];
  proofs: ProofRun[];
  clusters: FindingCluster[];
  benchmarks: BenchmarkReport[];
  surfaceGraph: TargetSurfaceGraph | null;
}

const emptyData: PanelData = {
  candidates: [],
  verdicts: [],
  proofs: [],
  clusters: [],
  benchmarks: [],
  surfaceGraph: null,
};

const statusColor: Record<string, string> = {
  candidate: '#4e5ced',
  proof_queued: '#1565c0',
  proof_running: '#7b1fa2',
  proven: '#2e7d32',
  proof_failed: '#b53030',
  promoted: '#137a4e',
  ruled_out: '#8a93a6',
  source_verified_unreachable: '#8a93a6',
  source_verified_needs_replay: '#ed6c02',
};

const verdictColor: Record<string, string> = {
  support: '#2e7d32',
  refute: '#b53030',
  disputed: '#ed6c02',
  'needs-proof': '#4e5ced',
};

const severityColor: Record<string, string> = {
  critical: '#f44336',
  high: '#ff6d00',
  medium: '#ff9800',
  low: '#2979ff',
  info: '#5a6478',
};

const clip = (value: unknown, max = 120): string => {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max)}...` : text;
};

const fmtPct = (value: number | null | undefined): string => {
  if (value == null || Number.isNaN(Number(value))) return 'n/a';
  return `${Math.round(Number(value) * 100)}%`;
};

const fmtTime = (value: string | null | undefined): string => {
  if (!value) return '';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
};

const confirmResultMessage = (result: ConfirmFindingsResult): { severity: 'success' | 'info' | 'warning'; text: string } => {
  const remaining = result.remaining;
  const blockers: string[] = [];
  if (remaining.missing_proof_count > 0) blockers.push(`${remaining.missing_proof_count} need proof`);
  if (remaining.live_replay_needed_count > 0) blockers.push(`${remaining.live_replay_needed_count} need live replay`);
  if (remaining.blocked_refute_count > 0) blockers.push(`${remaining.blocked_refute_count} have refutations`);
  if (remaining.missing_support_count > 0) blockers.push(`${remaining.missing_support_count} need support`);

  if (result.promoted_count > 0) {
    const tail = blockers.length > 0 ? ` Remaining blockers: ${blockers.join(', ')}.` : '';
    return {
      severity: 'success',
      text: `Confirmed ${result.promoted_count} finding${result.promoted_count === 1 ? '' : 's'}.${tail}`,
    };
  }
  if (blockers.length > 0) {
    const example = remaining.examples?.[0]?.title ? ` Example: ${remaining.examples[0].title} (${remaining.examples[0].reason}).` : '';
    return { severity: 'warning', text: `No candidate promotions were created because ${blockers.join(', ')}.${example}` };
  }
  return { severity: 'info', text: 'No eligible unpromoted candidates were found.' };
};

const CountChip: React.FC<{ label: string; value: number | string; color?: string }> = ({ label, value, color = '#4e5ced' }) => (
  <Chip
    size="small"
    label={`${label}: ${value}`}
    sx={{
      backgroundColor: `${color}17`,
      color,
      border: `1px solid ${color}33`,
      fontSize: '0.68rem',
      height: 22,
      fontWeight: 700,
    }}
  />
);

const PipelineStep: React.FC<{ label: string; value: number; color: string }> = ({ label, value, color }) => (
  <Box sx={{ minWidth: 120, flex: '1 1 120px' }}>
    <Typography sx={{ color: '#5a6478', fontSize: '0.66rem', fontWeight: 700, textTransform: 'uppercase' }}>
      {label}
    </Typography>
    <Typography sx={{ color, fontSize: '1.1rem', fontWeight: 800, lineHeight: 1.15 }}>
      {value}
    </Typography>
    <LinearProgress
      variant="determinate"
      value={Math.min(100, value * 10)}
      sx={{
        height: 4,
        mt: 0.75,
        borderRadius: 1,
        backgroundColor: `${color}18`,
        '& .MuiLinearProgress-bar': { backgroundColor: color },
      }}
    />
  </Box>
);

const ValidatedScannerPanel: React.FC<Props> = ({ sessionId, sessionStatus }) => {
  const [tab, setTab] = useState(0);
  const [data, setData] = useState<PanelData>(emptyData);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [benchmarking, setBenchmarking] = useState(false);
  const [completingValidation, setCompletingValidation] = useState(false);
  const [proofJob, setProofJob] = useState<ValidationProofJob | null>(null);
  const [confirmingEligible, setConfirmingEligible] = useState(false);
  const [confirmingCandidate, setConfirmingCandidate] = useState<string | null>(null);
  const [confirmNotice, setConfirmNotice] = useState<{ severity: 'success' | 'info' | 'warning'; text: string } | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    Promise.all([
      validatedApi.listCandidates(sessionId, { limit: 500 }),
      validatedApi.listVerdicts(sessionId, { limit: 500 }),
      validatedApi.listProofRuns(sessionId, { limit: 500 }),
      validatedApi.listClusters(sessionId, { rebuild: true, limit: 500 }),
      validatedApi.listBenchmarkReports(sessionId, { limit: 20 }),
      validatedApi.getSurfaceGraph(sessionId, { rebuild: true }),
    ])
      .then(([candidateRes, verdictRes, proofRes, clusterRes, benchmarkRes, surfaceGraph]) => {
        setData({
          candidates: candidateRes.items,
          verdicts: verdictRes.items,
          proofs: proofRes.items,
          clusters: clusterRes.items,
          benchmarks: benchmarkRes.items,
          surfaceGraph,
        });
        setError(null);
      })
      .catch((exc) => setError(exc instanceof Error ? exc.message : 'Failed to load validated scanner data.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  const createBenchmark = useCallback(() => {
    setBenchmarking(true);
    validatedApi.createBenchmark(sessionId, { label: 'ui-scorecard' })
      .then(() => refresh())
      .catch((exc) => setError(exc instanceof Error ? exc.message : 'Failed to create benchmark report.'))
      .finally(() => setBenchmarking(false));
  }, [refresh, sessionId]);

  const completeValidation = useCallback(() => {
    const passedIds = new Set(data.proofs.filter(p => p.passed).map(p => p.candidate_id));
    const livePassedIds = new Set(data.proofs.filter(p => p.passed && p.proof_class === 'live').map(p => p.candidate_id));
    const sourceRequiresLive = (cand: CandidateFinding) => (
      Boolean(cand.source_context && (cand.source_context.repo || cand.source_context.file_path || cand.source_context.symbol))
      && cand.proof_plan?.live_replay_required !== false
    );
    const candidateIds = data.candidates
      .filter(c => !['promoted', 'ruled_out'].includes(c.status))
      .filter(c => !passedIds.has(c.candidate_id) || (sourceRequiresLive(c) && !livePassedIds.has(c.candidate_id)))
      .slice(0, 50)
      .map(c => c.candidate_id);
    setCompletingValidation(true);
    setConfirmNotice(null);
    validatedApi.completeValidation(sessionId, {
      candidate_ids: candidateIds,
      max_candidates: Math.max(1, candidateIds.length || 50),
      force_reproof: false,
    })
      .then((result) => {
        setConfirmNotice({
          severity: result.queued_count > 0 ? 'info' : 'success',
          text: result.queued_count > 0
            ? `Validation completion queued ${result.queued_count} candidate${result.queued_count === 1 ? '' : 's'} for proof.`
            : 'No candidates need proof right now.',
        });
        if (result.job_id) {
          validatedApi.getProofJob(sessionId, result.job_id)
            .then(setProofJob)
            .catch(() => setProofJob(null));
        }
        refresh();
      })
      .catch((exc) => setError(exc instanceof Error ? exc.message : 'Failed to complete validation.'))
      .finally(() => setCompletingValidation(false));
  }, [data.candidates, data.proofs, refresh, sessionId]);

  useEffect(() => {
    if (!proofJob || !['queued', 'running'].includes(proofJob.status)) return undefined;
    const handle = window.setInterval(() => {
      validatedApi.getProofJob(sessionId, proofJob.job_id)
        .then((job) => {
          setProofJob(job);
          if (!['queued', 'running'].includes(job.status)) {
            refresh();
            setConfirmNotice({
              severity: job.status === 'completed' ? 'success' : 'warning',
              text: job.status === 'completed'
                ? `Validation completed: ${job.passed_count} proof${job.passed_count === 1 ? '' : 's'} passed, ${job.promoted_count} finding${job.promoted_count === 1 ? '' : 's'} confirmed.`
                : `Validation job failed: ${job.error || 'see backend logs'}`,
            });
          }
        })
        .catch((exc) => setError(exc instanceof Error ? exc.message : 'Failed to poll validation job.'));
    }, 5000);
    return () => window.clearInterval(handle);
  }, [proofJob, refresh, sessionId]);

  const promoteProvenCandidates = useCallback(() => {
    setConfirmingEligible(true);
    setConfirmNotice(null);
    validatedApi.confirmFindings(sessionId, {})
      .then((result) => {
        setConfirmNotice(confirmResultMessage(result));
        refresh();
      })
      .catch((exc) => setError(exc instanceof Error ? exc.message : 'Failed to promote proven candidates.'))
      .finally(() => setConfirmingEligible(false));
  }, [refresh, sessionId]);

  const operatorConfirmCandidate = useCallback((candidate: CandidateFinding) => {
    setConfirmingCandidate(candidate.candidate_id);
    setConfirmNotice(null);
    validatedApi.confirmFindings(sessionId, {
      candidate_ids: [candidate.candidate_id],
      operator_validated: true,
      reason: `Operator confirmed from Validation Lab: ${candidate.title}`,
    })
      .then((result) => {
        setConfirmNotice(confirmResultMessage(result));
        refresh();
      })
      .catch((exc) => setError(exc instanceof Error ? exc.message : 'Failed to operator-confirm candidate.'))
      .finally(() => setConfirmingCandidate(null));
  }, [refresh, sessionId]);

  const verdictsByCandidate = useMemo(() => {
    const map: Record<string, ValidationVerdict[]> = {};
    for (const verdict of data.verdicts) {
      const key = verdict.candidate_id;
      map[key] = [...(map[key] ?? []), verdict];
    }
    return map;
  }, [data.verdicts]);

  const proofsByCandidate = useMemo(() => {
    const map: Record<string, ProofRun[]> = {};
    for (const proof of data.proofs) {
      const key = proof.candidate_id;
      map[key] = [...(map[key] ?? []), proof];
    }
    return map;
  }, [data.proofs]);

  const counts = useMemo(() => {
    const passedIds = new Set(data.proofs.filter(p => p.passed).map(p => p.candidate_id));
    const livePassedIds = new Set(data.proofs.filter(p => p.passed && p.proof_class === 'live').map(p => p.candidate_id));
    const sourceRequiresLive = (cand: CandidateFinding) => (
      Boolean(cand.source_context && (cand.source_context.repo || cand.source_context.file_path || cand.source_context.symbol))
      && cand.proof_plan?.live_replay_required !== false
    );
    const byStatus = data.candidates.reduce<Record<string, number>>((acc, cand) => {
      acc[cand.status] = (acc[cand.status] ?? 0) + 1;
      return acc;
    }, {});
    const byVerdict = data.verdicts.reduce<Record<string, number>>((acc, verdict) => {
      acc[verdict.verdict] = (acc[verdict.verdict] ?? 0) + 1;
      return acc;
    }, {});
    return {
      byStatus,
      byVerdict,
      passedProofs: data.proofs.filter(p => p.passed).length,
      liveProofs: data.proofs.filter(p => p.passed && p.proof_class === 'live').length,
      staticProofs: data.proofs.filter(p => p.passed && p.proof_class === 'static').length,
      failedProofs: data.proofs.filter(p => !p.passed).length,
      duplicates: data.clusters.reduce((acc, cluster) => acc + Math.max(0, cluster.candidate_count - 1), 0),
      endpointCandidates: data.candidates.filter(c => c.candidate_kind === 'endpoint').length,
      sourceCandidates: data.candidates.filter(c => c.candidate_kind === 'source').length,
      hybridCandidates: data.candidates.filter(c => c.candidate_kind === 'hybrid').length,
      needsProof: data.candidates.filter(c => (
        !['promoted', 'ruled_out'].includes(c.status)
        && (!passedIds.has(c.candidate_id) || (sourceRequiresLive(c) && !livePassedIds.has(c.candidate_id)))
      )).length,
    };
  }, [data]);

  if (loading && data.candidates.length === 0 && data.verdicts.length === 0) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress size={28} /></Box>;
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: 0, height: '100%' }}>
      <Box sx={{ px: 2, py: 1.25, borderBottom: '1px solid #dfe3ec', display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
        <FactCheckIcon sx={{ color: '#4e5ced', fontSize: 20 }} />
        <Typography sx={{ color: '#1a1f2e', fontWeight: 800, fontSize: '0.95rem' }}>
          Validation Lab
        </Typography>
        <CountChip label="candidates" value={data.candidates.length} />
        <CountChip label="hybrid" value={counts.hybridCandidates} color="#1565c0" />
        <CountChip label="source" value={counts.sourceCandidates} color="#7b1fa2" />
        <CountChip label="proofs passed" value={counts.passedProofs} color="#2e7d32" />
        <CountChip label="need proof" value={counts.needsProof} color="#b8740c" />
        <CountChip label="promoted" value={counts.byStatus.promoted ?? 0} color="#137a4e" />
        <CountChip label="duplicates" value={counts.duplicates} color="#ed6c02" />
        <Box sx={{ flexGrow: 1 }} />
        <Chip
          size="small"
          label={sessionStatus ?? 'session'}
          sx={{ backgroundColor: '#eef1ff', color: '#4e5ced', height: 22, fontSize: '0.68rem', fontWeight: 700 }}
        />
        <Tooltip title="Refresh">
          <IconButton size="small" onClick={refresh}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Button
          size="small"
          variant="outlined"
          startIcon={completingValidation ? <CircularProgress size={12} /> : <ScienceIcon fontSize="small" />}
          onClick={completeValidation}
          disabled={completingValidation || counts.needsProof === 0}
          sx={{ fontSize: '0.72rem', textTransform: 'none', color: '#1565c0', borderColor: 'rgba(21,101,192,0.35)' }}
        >
          Complete Validation
        </Button>
        <Button
          size="small"
          variant="contained"
          startIcon={confirmingEligible ? <CircularProgress size={12} color="inherit" /> : <CheckCircleIcon fontSize="small" />}
          onClick={promoteProvenCandidates}
          disabled={confirmingEligible || data.candidates.length === 0}
          sx={{ fontSize: '0.72rem', textTransform: 'none', backgroundColor: '#137a4e', '&:hover': { backgroundColor: '#0f623f' } }}
        >
          Promote Proven
        </Button>
        <Button
          size="small"
          variant="outlined"
          startIcon={benchmarking ? <CircularProgress size={12} /> : <VerifiedIcon fontSize="small" />}
          onClick={createBenchmark}
          disabled={benchmarking}
          sx={{ fontSize: '0.72rem', textTransform: 'none', color: '#4e5ced', borderColor: 'rgba(78,92,237,0.35)' }}
        >
          Scorecard
        </Button>
      </Box>

      {error && (
        <Box sx={{ px: 2, py: 1, borderBottom: '1px solid rgba(181,48,48,0.18)', backgroundColor: 'rgba(181,48,48,0.06)' }}>
          <Typography sx={{ color: '#b53030', fontSize: '0.76rem' }}>{error}</Typography>
        </Box>
      )}
      {confirmNotice && (
        <Alert severity={confirmNotice.severity} sx={{ borderRadius: 0, py: 0.5, '& .MuiAlert-message': { fontSize: '0.76rem' } }}>
          {confirmNotice.text}
        </Alert>
      )}
      {proofJob && ['queued', 'running'].includes(proofJob.status) && (
        <Alert severity="info" sx={{ borderRadius: 0, py: 0.5, '& .MuiAlert-message': { fontSize: '0.76rem' } }}>
          Complete Validation is {proofJob.status}: {proofJob.processed_count}/{proofJob.queued_count} processed, {proofJob.passed_count} passed, {proofJob.failed_count} failed.
        </Alert>
      )}
      <Alert severity="info" sx={{ borderRadius: 0, py: 0.5, '& .MuiAlert-message': { fontSize: '0.76rem' } }}>
        This lab is optional evidence follow-up. Findings now appear in the Findings tab after GENESIS evidence checks and critic review; Complete Validation can add proof runs, promotion records, and scorecards for candidates that need deeper review.
      </Alert>

      <Box sx={{ px: 2, py: 1.25, borderBottom: '1px solid #dfe3ec', display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <PipelineStep label="Prepare" value={data.surfaceGraph?.link_count ?? 0} color="#1565c0" />
        <PipelineStep label="Scan" value={data.candidates.length} color="#4e5ced" />
        <PipelineStep label="Validate" value={data.verdicts.length} color="#7b1fa2" />
        <PipelineStep label="Dedup" value={counts.duplicates} color="#ed6c02" />
        <PipelineStep label="Prove" value={counts.passedProofs} color="#2e7d32" />
        <PipelineStep label="Report" value={counts.byStatus.promoted ?? 0} color="#137a4e" />
      </Box>

      <Tabs
        value={tab}
        onChange={(_, value) => setTab(value)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{
          minHeight: 36,
          borderBottom: '1px solid #dfe3ec',
          '& .MuiTab-root': { minHeight: 36, fontSize: '0.72rem', textTransform: 'none', py: 0.25 },
        }}
      >
        <Tab icon={<FactCheckIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Candidates (${data.candidates.length})`} />
        <Tab icon={<AccountTreeIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Surface (${data.surfaceGraph?.link_count ?? 0})`} />
        <Tab icon={<VerifiedIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Debate (${data.verdicts.length})`} />
        <Tab icon={<ScienceIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Proof (${data.proofs.length})`} />
        <Tab icon={<AccountTreeIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Clusters (${data.clusters.length})`} />
        <Tab icon={<VerifiedIcon sx={{ fontSize: 15 }} />} iconPosition="start" label={`Scorecards (${data.benchmarks.length})`} />
      </Tabs>

      <Box sx={{ flexGrow: 1, minHeight: 0, overflow: 'auto', p: 1.25 }}>
        {tab === 0 && (
          <TableContainer sx={{ border: '1px solid #e0e3eb', borderRadius: 1 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Candidate</TableCell>
                  <TableCell sx={{ width: 110 }}>Severity</TableCell>
                  <TableCell sx={{ width: 120 }}>Status</TableCell>
                  <TableCell sx={{ width: 120 }}>Validation</TableCell>
                  <TableCell sx={{ width: 110 }}>Proof</TableCell>
                  <TableCell sx={{ width: 90 }}>Confidence</TableCell>
                  <TableCell sx={{ width: 150 }}>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.candidates.length === 0 ? (
                  <TableRow><TableCell colSpan={7}><Typography sx={{ color: '#8a93a6', fontSize: '0.8rem' }}>No candidates recorded yet.</Typography></TableCell></TableRow>
                ) : data.candidates.map(candidate => {
                  const verdicts = verdictsByCandidate[candidate.candidate_id] ?? [];
                  const proofs = proofsByCandidate[candidate.candidate_id] ?? [];
                  const lastVerdict = verdicts[0]?.verdict ?? 'none';
                  const passed = proofs.some(p => p.passed);
                  const canConfirm = !['promoted', 'ruled_out'].includes(candidate.status);
                  return (
                    <TableRow key={candidate.candidate_id} hover>
                      <TableCell>
                        <Typography sx={{ fontSize: '0.78rem', fontWeight: 700, color: '#1a1f2e' }}>{candidate.title}</Typography>
                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', my: 0.25 }}>
                          <Chip size="small" label={candidate.candidate_kind || 'endpoint'} sx={{ height: 18, fontSize: '0.6rem', backgroundColor: candidate.candidate_kind === 'hybrid' ? 'rgba(21,101,192,0.12)' : candidate.candidate_kind === 'source' ? 'rgba(123,31,162,0.12)' : 'rgba(78,92,237,0.10)', color: candidate.candidate_kind === 'hybrid' ? '#1565c0' : candidate.candidate_kind === 'source' ? '#7b1fa2' : '#4e5ced' }} />
                          {candidate.source_context?.file_path && (
                            <Chip size="small" label={clip(candidate.source_context.file_path, 48)} sx={{ height: 18, fontSize: '0.6rem', backgroundColor: 'rgba(123,31,162,0.08)', color: '#7b1fa2' }} />
                          )}
                        </Box>
                        <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', fontFamily: 'monospace' }}>
                          {candidate.attack_class || 'class:unknown'} @ {clip(candidate.affected_surface || candidate.endpoint || candidate.affected_service, 80)}
                        </Typography>
                        {(candidate.sink || candidate.source_input) && (
                          <Typography sx={{ fontSize: '0.68rem', color: '#7b1fa2', fontFamily: 'monospace' }}>
                            {clip(candidate.source_input || 'input', 60)} -&gt; {clip(candidate.sink || 'sink', 80)}
                          </Typography>
                        )}
                        <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{clip(candidate.hypothesis, 160)}</Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={candidate.severity || 'info'}
                          sx={{ height: 20, fontSize: '0.65rem', backgroundColor: `${severityColor[candidate.severity] ?? '#5a6478'}18`, color: severityColor[candidate.severity] ?? '#5a6478' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={candidate.status}
                          sx={{ height: 20, fontSize: '0.65rem', backgroundColor: `${statusColor[candidate.status] ?? '#5a6478'}18`, color: statusColor[candidate.status] ?? '#5a6478' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={lastVerdict}
                          sx={{ height: 20, fontSize: '0.65rem', backgroundColor: `${verdictColor[lastVerdict] ?? '#8a93a6'}18`, color: verdictColor[lastVerdict] ?? '#8a93a6' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={passed ? 'passed' : proofs.length > 0 ? 'failed' : 'pending'}
                          sx={{ height: 20, fontSize: '0.65rem', backgroundColor: passed ? 'rgba(46,125,50,0.12)' : 'rgba(138,147,166,0.12)', color: passed ? '#2e7d32' : '#8a93a6' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.74rem', color: '#5a6478' }}>
                          {Math.round((candidate.confidence ?? 0) * 100)}%
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title="Manual override: record your operator validation and try to promote this candidate">
                          <span>
                            <Button
                              size="small"
                              variant="outlined"
                              startIcon={confirmingCandidate === candidate.candidate_id ? <CircularProgress size={12} /> : <CheckCircleIcon fontSize="small" />}
                              disabled={!canConfirm || confirmingCandidate === candidate.candidate_id || confirmingEligible}
                              onClick={() => operatorConfirmCandidate(candidate)}
                              sx={{ fontSize: '0.68rem', minWidth: 126, textTransform: 'none', color: '#137a4e', borderColor: 'rgba(19,122,78,0.35)' }}
                            >
                              Operator Confirm
                            </Button>
                          </span>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {tab === 1 && (
          <TableContainer sx={{ border: '1px solid #e0e3eb', borderRadius: 1 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Endpoint</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell sx={{ width: 140 }}>Candidate</TableCell>
                  <TableCell sx={{ width: 120 }}>Confidence</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {!data.surfaceGraph || (data.surfaceGraph.links ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={4}><Typography sx={{ color: '#8a93a6', fontSize: '0.8rem' }}>No endpoint/source surface links recorded yet.</Typography></TableCell></TableRow>
                ) : (data.surfaceGraph.links ?? []).map(link => (
                  <TableRow key={link.link_id} hover>
                    <TableCell>
                      <Typography sx={{ fontSize: '0.76rem', color: '#1a1f2e', fontFamily: 'monospace' }}>
                        {link.method ? `${link.method} ` : ''}{link.endpoint || '(no live endpoint)'}
                      </Typography>
                      {link.attack_class && <Typography sx={{ fontSize: '0.68rem', color: '#5a6478' }}>{link.attack_class}</Typography>}
                    </TableCell>
                    <TableCell>
                      <Typography sx={{ fontSize: '0.74rem', color: '#7b1fa2', fontFamily: 'monospace' }}>
                        {clip(link.file_path || '(no source file)', 90)}
                      </Typography>
                      {link.handler_symbol && <Typography sx={{ fontSize: '0.68rem', color: '#5a6478' }}>{link.handler_symbol}</Typography>}
                    </TableCell>
                    <TableCell>
                      <Chip size="small" label={link.candidate_kind || 'surface'} sx={{ height: 20, fontSize: '0.65rem', backgroundColor: link.candidate_kind === 'hybrid' ? 'rgba(21,101,192,0.12)' : 'rgba(138,147,166,0.12)', color: link.candidate_kind === 'hybrid' ? '#1565c0' : '#5a6478' }} />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{Math.round((link.confidence ?? 0) * 100)}%</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {tab === 2 && (
          <TableContainer sx={{ border: '1px solid #e0e3eb', borderRadius: 1 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Candidate</TableCell>
                  <TableCell sx={{ width: 140 }}>Verdict</TableCell>
                  <TableCell>Reasoning</TableCell>
                  <TableCell sx={{ width: 170 }}>Validator</TableCell>
                  <TableCell sx={{ width: 170 }}>Created</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.verdicts.length === 0 ? (
                  <TableRow><TableCell colSpan={5}><Typography sx={{ color: '#8a93a6', fontSize: '0.8rem' }}>No validation verdicts recorded yet.</Typography></TableCell></TableRow>
                ) : data.verdicts.map(verdict => (
                  <TableRow key={verdict._id} hover>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.72rem' }}>{verdict.candidate_id}</TableCell>
                    <TableCell>
                      <Chip size="small" label={verdict.verdict} sx={{ height: 20, fontSize: '0.65rem', backgroundColor: `${verdictColor[verdict.verdict] ?? '#8a93a6'}18`, color: verdictColor[verdict.verdict] ?? '#8a93a6' }} />
                    </TableCell>
                    <TableCell>
                      <Typography sx={{ fontSize: '0.74rem', color: '#2a3045' }}>{clip(verdict.reasoning, 220)}</Typography>
                      {verdict.missing_evidence.length > 0 && (
                        <Typography sx={{ fontSize: '0.68rem', color: '#b8740c' }}>{verdict.missing_evidence.join(', ')}</Typography>
                      )}
                    </TableCell>
                    <TableCell sx={{ fontSize: '0.72rem', color: '#5a6478' }}>{verdict.validator}</TableCell>
                    <TableCell sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{fmtTime(verdict.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {tab === 3 && (
          <TableContainer sx={{ border: '1px solid #e0e3eb', borderRadius: 1 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Candidate</TableCell>
                  <TableCell sx={{ width: 150 }}>Tool</TableCell>
                  <TableCell sx={{ width: 100 }}>Result</TableCell>
                  <TableCell>Reason</TableCell>
                  <TableCell sx={{ width: 170 }}>Created</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.proofs.length === 0 ? (
                  <TableRow><TableCell colSpan={5}><Typography sx={{ color: '#8a93a6', fontSize: '0.8rem' }}>No proof runs recorded yet.</Typography></TableCell></TableRow>
                ) : data.proofs.map(proof => (
                  <TableRow key={proof._id} hover>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.72rem' }}>{proof.candidate_id}</TableCell>
                    <TableCell sx={{ fontSize: '0.72rem', color: '#5a6478' }}>{proof.proof_tool}</TableCell>
                    <TableCell>
                      <Chip size="small" label={proof.passed ? `passed:${proof.proof_class ?? 'proof'}` : 'failed'} sx={{ height: 20, fontSize: '0.65rem', backgroundColor: proof.passed ? 'rgba(46,125,50,0.12)' : 'rgba(181,48,48,0.12)', color: proof.passed ? '#2e7d32' : '#b53030' }} />
                      {proof.live_replay_required && proof.proof_class !== 'live' && (
                        <Typography sx={{ fontSize: '0.64rem', color: '#ed6c02', mt: 0.25 }}>needs live replay</Typography>
                      )}
                    </TableCell>
                    <TableCell sx={{ fontSize: '0.74rem', color: '#2a3045' }}>{clip(proof.pass_fail_reason || JSON.stringify(proof.result), 260)}</TableCell>
                    <TableCell sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{fmtTime(proof.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {tab === 4 && (
          <TableContainer sx={{ border: '1px solid #e0e3eb', borderRadius: 1 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Cluster</TableCell>
                  <TableCell sx={{ width: 120 }}>Candidates</TableCell>
                  <TableCell sx={{ width: 120 }}>Duplicates</TableCell>
                  <TableCell>Root Cause</TableCell>
                  <TableCell sx={{ width: 170 }}>Updated</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.clusters.length === 0 ? (
                  <TableRow><TableCell colSpan={5}><Typography sx={{ color: '#8a93a6', fontSize: '0.8rem' }}>No clusters recorded yet.</Typography></TableCell></TableRow>
                ) : data.clusters.map(cluster => (
                  <TableRow key={cluster.cluster_id} hover>
                    <TableCell>
                      <Typography sx={{ fontSize: '0.78rem', fontWeight: 700, color: '#1a1f2e' }}>{cluster.title}</Typography>
                      <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', fontFamily: 'monospace' }}>{cluster.attack_class} @ {clip(cluster.affected_surface, 90)}</Typography>
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{cluster.candidate_count}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{cluster.duplicates.length}</TableCell>
                    <TableCell sx={{ fontSize: '0.74rem', color: '#2a3045' }}>{clip(cluster.root_cause_summary, 240)}</TableCell>
                    <TableCell sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{fmtTime(cluster.updated_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {tab === 5 && (
          <TableContainer sx={{ border: '1px solid #e0e3eb', borderRadius: 1 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Report</TableCell>
                  <TableCell sx={{ width: 120 }}>Recall</TableCell>
                  <TableCell sx={{ width: 120 }}>Precision</TableCell>
                  <TableCell sx={{ width: 130 }}>Proof Coverage</TableCell>
                  <TableCell sx={{ width: 120 }}>Duplicate Rate</TableCell>
                  <TableCell sx={{ width: 170 }}>Created</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.benchmarks.length === 0 ? (
                  <TableRow><TableCell colSpan={6}><Typography sx={{ color: '#8a93a6', fontSize: '0.8rem' }}>No benchmark scorecards recorded yet.</Typography></TableCell></TableRow>
                ) : data.benchmarks.map(report => (
                  <TableRow key={report._id} hover>
                    <TableCell>
                      <Typography sx={{ fontSize: '0.78rem', fontWeight: 700, color: '#1a1f2e' }}>{report.label || 'scorecard'}</Typography>
                      <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', fontFamily: 'monospace' }}>
                        {report.candidate_count} candidates / {report.confirmed_vulnerability_count} confirmed
                      </Typography>
                      <Typography sx={{ fontSize: '0.68rem', color: '#5a6478', fontFamily: 'monospace' }}>
                        endpoint {report.endpoint_candidate_count ?? 0} / source {report.source_candidate_count ?? 0} / hybrid {report.hybrid_candidate_count ?? 0}
                      </Typography>
                      <Typography sx={{ fontSize: '0.68rem', color: '#5a6478', fontFamily: 'monospace' }}>
                        live proofs {report.live_proof_count ?? 0} / static proofs {report.static_proof_count ?? 0} / mapped {fmtPct(report.endpoint_source_mapping_rate)}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{fmtPct(report.recall)}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{fmtPct(report.precision_proxy)}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{fmtPct(report.proof_coverage)}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.74rem' }}>{fmtPct(report.duplicate_rate)}</TableCell>
                    <TableCell sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{fmtTime(report.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>
    </Box>
  );
};

export default ValidatedScannerPanel;

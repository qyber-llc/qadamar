import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api/client';
import type { ChangeKind, ChangePayload, ChangeRecord, Impact } from '../api/types';

export interface CandidateChange {
  readonly kind: ChangeKind;
  readonly payload: ChangePayload;
}

interface PreviewSnapshot {
  readonly key: string;
  readonly kind: ChangeKind;
  readonly payload: ChangePayload;
  readonly impact: Impact;
}

export function useChangePreview(candidate: CandidateChange | null) {
  const [preview, setPreview] = useState<PreviewSnapshot | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [submittedChange, setSubmittedChange] = useState<ChangeRecord | null>(null);
  const reqGenRef = useRef(0);
  const inFlightKeyRef = useRef<string | null>(null);

  const currentKey = useMemo(() => (candidate ? JSON.stringify(candidate) : null), [candidate]);

  useEffect(() => {
    if (inFlightKeyRef.current !== null && inFlightKeyRef.current !== currentKey) {
      reqGenRef.current += 1;
      inFlightKeyRef.current = null;
      setSimulating(false);
    }
    setPreview((prev) => (prev && prev.key === currentKey ? prev : null));
    setError(null);
    setSubmittedChange(null);
  }, [currentKey]);

  const activePreview = preview && currentKey !== null && preview.key === currentKey ? preview : null;
  const impact: Impact | null = activePreview ? activePreview.impact : null;
  const hasValidPreview = activePreview !== null;

  const runPreview = useCallback(
    async (overrideCandidate?: CandidateChange) => {
      const target = overrideCandidate ?? candidate;
      const snapKey = target ? JSON.stringify(target) : null;
      if (!target || !snapKey) return;
      const gen = ++reqGenRef.current;
      inFlightKeyRef.current = snapKey;
      const snapKind = target.kind;
      const snapPayload = target.payload;
      setSimulating(true);
      setError(null);
      setSubmittedChange(null);
      try {
        const imp = await api.simulateImpact({ kind: snapKind, payload: snapPayload });
        if (reqGenRef.current !== gen) return;
        inFlightKeyRef.current = null;
        setPreview({ key: snapKey, kind: snapKind, payload: snapPayload, impact: imp });
      } catch (err) {
        if (reqGenRef.current !== gen) return;
        inFlightKeyRef.current = null;
        setPreview(null);
        setError(err);
      } finally {
        if (reqGenRef.current === gen) {
          setSimulating(false);
        }
      }
    },
    [candidate],
  );

  const submitPreviewedChange = useCallback(
    async (
      reason: string,
      customSubmitter?: (previewed: {
        readonly kind: ChangeKind;
        readonly payload: ChangePayload;
        readonly reason: string;
      }) => Promise<ChangeRecord>,
    ): Promise<ChangeRecord | null> => {
      const trimmedReason = reason.trim();
      if (!activePreview || trimmedReason.length < 20) return null;
      setSubmitting(true);
      setError(null);
      setSubmittedChange(null);
      try {
        const chg = customSubmitter
          ? await customSubmitter({
              kind: activePreview.kind,
              payload: activePreview.payload,
              reason: trimmedReason,
            })
          : await api.createChange({
              kind: activePreview.kind,
              payload: activePreview.payload,
              reason: trimmedReason,
            });
        setSubmittedChange(chg);
        setPreview({
          key: activePreview.key,
          kind: activePreview.kind,
          payload: activePreview.payload,
          impact: chg.impact,
        });
        return chg;
      } catch (err) {
        setError(err);
        return null;
      } finally {
        setSubmitting(false);
      }
    },
    [activePreview],
  );

  const resetPreview = useCallback(() => {
    reqGenRef.current += 1;
    inFlightKeyRef.current = null;
    setSimulating(false);
    setPreview(null);
    setError(null);
    setSubmittedChange(null);
  }, []);

  return {
    impact,
    hasValidPreview,
    simulating,
    submitting,
    error,
    submittedChange,
    runPreview,
    submitPreviewedChange,
    resetPreview,
  };
}

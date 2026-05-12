import { create } from 'zustand';
import type { AppSettings, Session, HealthStatus } from '../types';

interface Store {
  settings: AppSettings | null;
  sessions: Session[];
  health: HealthStatus | null;
  setSettings: (s: AppSettings) => void;
  setSessions: (s: Session[]) => void;
  updateSession: (id: string, updates: Partial<Session>) => void;
  setHealth: (h: HealthStatus) => void;
}

export const useStore = create<Store>((set) => ({
  settings: null,
  sessions: [],
  health: null,
  setSettings: (settings) => set({ settings }),
  setSessions: (sessions) => set({ sessions }),
  updateSession: (id, updates) =>
    set(s => ({
      sessions: s.sessions.map(sess =>
        sess.id === id ? { ...sess, ...updates } : sess
      ),
    })),
  setHealth: (health) => set({ health }),
}));

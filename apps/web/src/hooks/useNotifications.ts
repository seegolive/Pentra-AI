import { create } from "zustand";

export type NotificationType =
  | "FINDING_CONFIRMED"
  | "AWAITING_APPROVAL"
  | "ENGAGEMENT_COMPLETED"
  | "AGENT_ERROR"
  | "INFO";

export interface NotificationItem {
  id: string;
  type: NotificationType;
  title: string;
  description?: string;
  timestamp: string;
  read: boolean;
  engagementId?: string;
}

interface NotificationStore {
  items: NotificationItem[];
  unreadCount: number;
  addNotification: (n: Omit<NotificationItem, "id" | "read" | "timestamp">) => void;
  markAllRead: () => void;
  clearAll: () => void;
}

export const useNotificationStore = create<NotificationStore>((set) => ({
  items: [],
  unreadCount: 0,
  addNotification: (n) =>
    set((state) => {
      const item: NotificationItem = {
        ...n,
        id: crypto.randomUUID(),
        read: false,
        timestamp: new Date().toISOString(),
      };
      const items = [item, ...state.items].slice(0, 100);
      return { items, unreadCount: state.unreadCount + 1 };
    }),
  markAllRead: () =>
    set((state) => ({
      items: state.items.map((i) => ({ ...i, read: true })),
      unreadCount: 0,
    })),
  clearAll: () => set({ items: [], unreadCount: 0 }),
}));

export function useNotifications() {
  return useNotificationStore();
}

// Imperative helper for use outside components
export function addNotification(
  n: Omit<NotificationItem, "id" | "read" | "timestamp">
) {
  useNotificationStore.getState().addNotification(n);
}

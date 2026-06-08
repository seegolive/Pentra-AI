import { create } from "zustand";

export type ToastVariant = "success" | "error" | "warning" | "info";

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastStore {
  toasts: ToastItem[];
  add: (toast: Omit<ToastItem, "id">) => void;
  remove: (id: string) => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  add: (t) =>
    set((state) => ({
      toasts: [
        ...state.toasts,
        { ...t, id: crypto.randomUUID() },
      ].slice(-5), // keep at most 5 visible
    })),
  remove: (id) =>
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    })),
}));

// Imperative helpers — safe to call outside React components
export function toast(
  title: string,
  options?: { description?: string; variant?: ToastVariant }
) {
  useToastStore.getState().add({
    title,
    description: options?.description,
    variant: options?.variant ?? "info",
  });
}

export const toastSuccess = (title: string, description?: string) =>
  toast(title, { description, variant: "success" });

export const toastError = (title: string, description?: string) =>
  toast(title, { description, variant: "error" });

export const toastWarning = (title: string, description?: string) =>
  toast(title, { description, variant: "warning" });

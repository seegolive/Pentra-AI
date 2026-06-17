import type { Config } from "tailwindcss";

const config = {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Existing semantic tokens used throughout the app.
        background: "rgb(var(--background-rgb) / <alpha-value>)",
        foreground: "rgb(var(--foreground-rgb) / <alpha-value>)",
        card: {
          DEFAULT: "rgb(var(--card-rgb) / <alpha-value>)",
          foreground: "rgb(var(--card-foreground-rgb) / <alpha-value>)",
        },
        border: "rgb(var(--border-rgb) / <alpha-value>)",
        input: "rgb(var(--input-rgb) / <alpha-value>)",
        muted: {
          DEFAULT: "rgb(var(--muted-rgb) / <alpha-value>)",
          foreground: "rgb(var(--muted-foreground-rgb) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "rgb(var(--accent-rgb) / <alpha-value>)",
          foreground: "rgb(var(--accent-foreground-rgb) / <alpha-value>)",
        },
        primary: {
          DEFAULT: "rgb(var(--primary-rgb) / <alpha-value>)",
          foreground: "rgb(var(--primary-foreground-rgb) / <alpha-value>)",
        },

        // Pentra Design System v2 tokens from pentra-design-system.html.
        pentra: {
          bg: {
            void: "var(--bg-void)",
            base: "var(--bg-base)",
            panel: "var(--bg-panel)",
            card: "var(--bg-card)",
            hover: "var(--bg-hover)",
            active: "var(--bg-active)",
            input: "var(--bg-input)",
          },
          border: {
            DEFAULT: "var(--border)",
            light: "var(--border-light)",
            focus: "var(--border-focus)",
          },
          text: {
            primary: "var(--text-primary)",
            secondary: "var(--text-secondary)",
            muted: "var(--text-muted)",
            code: "var(--text-code)",
          },
          severity: {
            critical: "var(--critical)",
            high: "var(--high)",
            medium: "var(--medium)",
            low: "var(--low)",
            info: "var(--info)",
          },
          accent: {
            DEFAULT: "var(--accent)",
            glow: "var(--accent-glow)",
            light: "var(--accent-light)",
            dim: "var(--accent-dim)",
          },
          status: {
            running: "var(--status-running)",
            waiting: "var(--status-waiting)",
            complete: "var(--status-complete)",
            failed: "var(--status-failed)",
            idle: "var(--status-idle)",
          },
        },
      },
      spacing: {
        "ds-1": "var(--space-1)",
        "ds-2": "var(--space-2)",
        "ds-3": "var(--space-3)",
        "ds-4": "var(--space-4)",
        "ds-5": "var(--space-5)",
        "ds-6": "var(--space-6)",
        "ds-8": "var(--space-8)",
        "icon-nav": "var(--nav-w)",
        sidebar: "var(--sidebar-w)",
      },
      width: {
        "icon-nav": "var(--nav-w)",
        sidebar: "var(--sidebar-w)",
      },
      minWidth: {
        "icon-nav": "var(--nav-w)",
        sidebar: "var(--sidebar-w)",
      },
      maxWidth: {
        sidebar: "var(--sidebar-w)",
      },
      fontFamily: {
        ui: ["var(--font-ui)"],
        mono: ["var(--font-mono)"],
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
        "ds-sm": "var(--r-sm)",
        "ds-md": "var(--r-md)",
        "ds-lg": "var(--r-lg)",
        "ds-xl": "var(--r-xl)",
      },
      gridTemplateColumns: {
        shell: "var(--nav-w) var(--sidebar-w) minmax(0, 1fr)",
      },
    },
  },
  plugins: [],
} satisfies Config;

export default config;

import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Optional custom fallback UI — overrides the default error screen. */
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary] Uncaught error:", error, info.componentStack);
  }

  private reset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (!this.state.hasError) return this.props.children;

    if (this.props.fallback) return this.props.fallback;

    return (
      <div className="flex flex-col items-center justify-center h-full py-16 gap-3 text-muted-foreground">
        <AlertTriangle className="h-8 w-8 text-red-400 opacity-70" />
        <p className="text-sm font-medium text-foreground/70">
          Something went wrong
        </p>
        {this.state.error?.message && (
          <p className="text-xs opacity-60 max-w-sm text-center font-mono">
            {this.state.error.message}
          </p>
        )}
        <button
          onClick={this.reset}
          className="mt-2 flex items-center gap-1.5 px-4 py-2 text-xs bg-muted hover:bg-muted/80 rounded-md transition-colors"
        >
          <RefreshCw className="h-3 w-3" />
          Try again
        </button>
      </div>
    );
  }
}

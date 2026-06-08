/** Pentra AI — frontend version constant.
 *
 * Bump this together with the API version in apps/api/app/main.py
 * and the CHANGELOG.md entry whenever a release is cut.
 */
export const APP_VERSION = "1.0.0" as const;

/** Build timestamp injected at Vite build time (ISO string).
 *  Falls back to the constant if the env var is not set. */
export const BUILD_DATE: string =
  import.meta.env.VITE_BUILD_DATE ?? new Date().toISOString().slice(0, 10);

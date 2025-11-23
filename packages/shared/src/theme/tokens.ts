export type ThemeColorTokens = {
  ink: string;
  paper: string;
  accent: string;
  surface: string;
  surfaceRaised: string;
  border: string;
  primary: string;
  primaryLight: string;
  primaryDark: string;
  secondary: string;
  danger: string;
  warning: string;
  success: string;
  textPrimary: string;
  textSecondary: string;
  textTertiary: string;
  textInverse: string;
  accentLive: string;
  accentHeatStart: string;
  accentHeatEnd: string;
};

export type ThemeSpacingTokens = {
  xs: number;
  sm: number;
  md: number;
  lg: number;
  xl: number;
  xxl: number;
};

export type ThemeRadiusTokens = {
  sm: number;
  md: number;
  lg: number;
  xl: number;
  full: number;
};

export type ThemeShadowTokens = {
  sm: string;
  md: string;
  lg: string;
  xl: string;
};

export type ThemeFontTokens = {
  sans: string;
  mono: string;
};

export interface ThemeTokens {
  colors: ThemeColorTokens;
  spacing: ThemeSpacingTokens;
  radius: ThemeRadiusTokens;
  shadows: ThemeShadowTokens;
  fonts: ThemeFontTokens;
}

export const campusThemeTokens: ThemeTokens = {
  colors: {
    ink: '#031106',
    paper: '#e8eaed',
    accent: '#791217',
    surface: 'color-mix(in srgb, #e8eaed 95%, #031106 5%)',
    surfaceRaised: 'color-mix(in srgb, #e8eaed 98%, #031106 2%)',
    border: 'color-mix(in srgb, #031106 18%, transparent)',
    primary: '#791217',
    primaryLight: 'color-mix(in srgb, #791217 70%, #e8eaed 30%)',
    primaryDark: 'color-mix(in srgb, #791217 85%, #031106 15%)',
    secondary: 'color-mix(in srgb, #031106 70%, #e8eaed 30%)',
    danger: '#791217',
    warning: 'color-mix(in srgb, #791217 55%, #e8eaed 45%)',
    success: 'color-mix(in srgb, #031106 75%, #e8eaed 25%)',
    textPrimary: '#031106',
    textSecondary: 'color-mix(in srgb, #031106 65%, #e8eaed 35%)',
    textTertiary: 'color-mix(in srgb, #031106 45%, #e8eaed 55%)',
    textInverse: '#e8eaed',
    accentLive: '#791217',
    accentHeatStart: '#791217',
    accentHeatEnd: 'color-mix(in srgb, #791217 80%, #e8eaed 20%)'
  },
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
    xxl: 48
  },
  radius: {
    sm: 8,
    md: 12,
    lg: 16,
    xl: 24,
    full: 9999
  },
  shadows: {
    sm: '0 1px 0 color-mix(in srgb, #031106 10%, transparent)',
    md: '0 4px 6px color-mix(in srgb, #031106 12%, transparent)',
    lg: '0 10px 18px color-mix(in srgb, #031106 14%, transparent)',
    xl: '0 20px 30px color-mix(in srgb, #031106 16%, transparent)'
  },
  fonts: {
    sans: 'var(--font-geist-sans, "Inter"), system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    mono: 'var(--font-geist-mono, "JetBrains Mono"), ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace'
  }
};

export default campusThemeTokens;

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#0a0a0a',
          900: '#111111',
          850: '#161616',
          800: '#1a1a1a',
        },
        line: {
          DEFAULT: '#1f1f1f',
          light: '#262626',
        },
        /* Override sky-* with vivid violet so the whole app uses the
           new Void Neon palette automatically. */
        sky: {
          50:  '#f5f3ff',
          100: '#ede9fe',
          200: '#ddd6fe',
          300: '#c4b5fd',
          400: '#a78bfa',
          500: '#8b6ef5',  // main accent — vivid violet
          600: '#7c3aed',  // button / strong accent
          700: '#6d28d9',
          800: '#5b21b6',
          900: '#4c1d95',
          950: '#2e1065',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        none: '0',
        sm: '5px',
        DEFAULT: '7px',
        md: '9px',
        lg: '11px',
        xl: '13px',
        '2xl': '16px',
        '3xl': '22px',
        full: '9999px',
      },
    },
  },
  plugins: [],
}

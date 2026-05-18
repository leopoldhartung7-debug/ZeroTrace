/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#0a0a0a',
          900: '#111111',
          850: '#151515',
          800: '#1a1a1a',
          700: '#1f1f1f',
          600: '#262626',
        },
        accent: {
          DEFAULT: '#3b82f6',
          soft: 'rgba(59, 130, 246, 0.12)',
        },
        danger: '#dc2626',
        success: '#22c55e',
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'sans-serif',
        ],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(59,130,246,0.4), 0 0 16px rgba(59,130,246,0.25)',
      },
    },
  },
  plugins: [],
}

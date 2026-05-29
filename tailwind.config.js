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
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'fade-in-up': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'scale-in': {
          '0%': { opacity: '0', transform: 'scale(0.96)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        'pulse-glow': {
          '0%, 100%': {
            boxShadow: '0 0 0 1px rgba(59,130,246,0.4), 0 0 16px rgba(59,130,246,0.25)',
          },
          '50%': {
            boxShadow: '0 0 0 1px rgba(59,130,246,0.6), 0 0 26px rgba(59,130,246,0.5)',
          },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.4s ease-out both',
        'fade-in-up': 'fade-in-up 0.5s ease-out both',
        'scale-in': 'scale-in 0.35s ease-out both',
        'pulse-glow': 'pulse-glow 3.5s ease-in-out infinite',
        shimmer: 'shimmer 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}

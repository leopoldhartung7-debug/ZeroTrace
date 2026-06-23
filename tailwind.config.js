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
        /* Override every sky-* class with steel-silver so the whole app
           follows the ZT logo's monochrome palette automatically */
        sky: {
          50:  '#f5f5f8',
          100: '#eaeaee',
          200: '#d4d4dc',
          300: '#b8b8c8',
          400: '#9ea8be',
          500: '#848eb0',  // main accent — steel-blue-grey
          600: '#636c8a',  // button bg / strong accent
          700: '#4c5270',
          800: '#363a54',
          900: '#22253a',
          950: '#141620',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}

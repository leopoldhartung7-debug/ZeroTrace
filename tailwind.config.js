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
          50:  '#f6f6fa',
          100: '#ececf2',
          200: '#d7dae4',
          300: '#bcc1d4',
          400: '#aab3cd',
          500: '#939dbd',  // main accent — refined steel-silver
          600: '#727b9c',  // button bg / strong accent
          700: '#565d78',
          800: '#3a3f56',
          900: '#252a3c',
          950: '#161823',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      /* Balanced medium rounding for the command-center look.
         `full` is kept for pills/avatars/dots. */
      borderRadius: {
        none: '0',
        sm: '4px',
        DEFAULT: '6px',
        md: '7px',
        lg: '9px',
        xl: '11px',
        '2xl': '13px',
        '3xl': '18px',
        full: '9999px',
      },
    },
  },
  plugins: [],
}

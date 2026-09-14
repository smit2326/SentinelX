/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#070a12',
          surface: '#0d1322',
          card: '#11182c',
          cardHover: '#16203a',
          border: '#1f2d4d',
          accent: '#00F0FF',
          accentGlow: 'rgba(0, 240, 255, 0.15)',
          neonGreen: '#00FF66',
          neonAmber: '#FFB800',
          neonRed: '#FF2E54',
          neonPurple: '#9D00FF'
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 6s linear infinite',
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        }
      }
    },
  },
  plugins: [],
}

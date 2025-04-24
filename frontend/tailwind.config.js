/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  darkMode: 'class', // Enable dark mode based on a class
  theme: {
    extend: {
      colors: {
        purple: {
          500: '#8b5cf6', // purple for main highlights
          600: '#6b46c1', // darker purple for buttons and hover states
        },
        gray: {
          900: '#1a202c', // very dark gray for backgrounds
          800: '#2d3748', // gray for navbar and footer
          400: '#cbd5e0', // light gray for text
        },
      },
    },
  },
  plugins: [
  ],
};

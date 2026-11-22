/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./pages/**/*.{js,ts,jsx,tsx}", "./components/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        forge: {
          bg: "#080808",
          surface: "#11110F",
          raised: "#171612",
          border: "#292820",
          gold: "#D9B875",
          ivory: "#F2EBDD",
          amber: "#C89558",
          red: "#A85F5F",
          text: "#F2EBDD",
          muted: "#969286",
        },
      },
    },
  },
  plugins: [],
};

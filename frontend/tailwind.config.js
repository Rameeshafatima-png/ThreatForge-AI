/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./pages/**/*.{js,ts,jsx,tsx}", "./components/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        forge: {
          bg: "#070907",
          surface: "#101510",
          raised: "#171E17",
          border: "#263126",
          gold: "#B7F36B",
          ivory: "#F1F6EC",
          amber: "#9BD85B",
          red: "#E16D72",
          text: "#F1F6EC",
          muted: "#9AA69A",
        },
      },
    },
  },
  plugins: [],
};

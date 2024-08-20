/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        secondary: "rgb(71, 88, 117)",
        blueish: "#0C66E4",
        buttonBg: "#E9F2FF",
        buttonPrimary: "#2d2d2d",
        boardTextColor: "#626F86",
        boardBgColor: "#f7f8f9",
        labelColor: "#6B778C",
        issueHeading: "#172b4d",
      },
    },
  },
  plugins: [],
};

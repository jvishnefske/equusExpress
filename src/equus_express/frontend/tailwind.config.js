/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}", // Scan frontend JSX/JS files
    "../../**/*.py", // Scan Python files for Tailwind classes
    "../../**/*.html", // Scan HTML templates for Tailwind classes
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}

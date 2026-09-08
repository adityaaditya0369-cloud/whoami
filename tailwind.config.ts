import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: "#101820",
        slate: {
          950: "#0b1220",
        },
        signal: {
          DEFAULT: "#2F6DF6",
          dim: "#1E4FB8",
        },
        parchment: "#F6F5F1",
        line: "#E4E2DA",
      },
      fontFamily: {
        display: ["var(--font-display)"],
        mono: ["var(--font-mono)"],
        body: ["var(--font-body)"],
      },
      borderRadius: {
        sm: "3px",
      },
    },
  },
  plugins: [],
};

export default config;

import next from "eslint-config-next";

// Flat config. `next lint` was removed in Next 16, so `npm run lint` invokes
// ESLint directly and CI runs the same command.
const config = [
  {
    ignores: [".next/**", "node_modules/**", "out/**", "next-env.d.ts"],
  },
  ...next,
];

export default config;

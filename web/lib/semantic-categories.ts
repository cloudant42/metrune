export const semanticTaxonomyVersion = "2026-01";

export const semanticCategories = [
  {
    id: "implementation",
    label: "Implementation",
    description: "Build or change product behavior, features, integrations, or application code.",
  },
  {
    id: "debugging",
    label: "Debugging",
    description: "Find the cause of incorrect behavior and fix a defect or failure.",
  },
  {
    id: "research",
    label: "Research",
    description: "Investigate a topic, codebase, or options where the main outcome is understanding.",
  },
  {
    id: "documentation",
    label: "Documentation",
    description: "Create or update technical explanations, guides, READMEs, or API documentation.",
  },
  {
    id: "review_refactoring",
    label: "Review & refactoring",
    description: "Assess or restructure existing code to improve quality without intentionally changing behavior.",
  },
  {
    id: "testing",
    label: "Testing",
    description: "Create, maintain, or run tests where verification is the main goal.",
  },
  {
    id: "planning",
    label: "Planning",
    description: "Define requirements, architecture, or an implementation approach before making changes.",
  },
  {
    id: "operations",
    label: "Operations",
    description: "Set up or operate environments, builds, CI/CD, releases, deployments, infrastructure, or dependencies.",
  },
  {
    id: "content",
    label: "Content",
    description: "Create or edit user-facing text or other non-code material that is not technical documentation.",
  },
  {
    id: "unknown",
    label: "Unknown",
    description: "No supported purpose is clear or dominant from the available session evidence.",
  },
] as const;

export type SemanticCategoryId = (typeof semanticCategories)[number]["id"];

export function semanticCategory(value: string) {
  return semanticCategories.find(category => category.id === value);
}

export function semanticCategoryLabel(value: string) {
  return semanticCategory(value)?.label;
}

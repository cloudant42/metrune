use crate::CategoryId;

/// The fixed semantic taxonomy used to classify one primary purpose per
/// coding-agent session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticCategory {
    pub id: CategoryId,
    pub label: &'static str,
    pub description: &'static str,
}

pub const SEMANTIC_CATEGORIES: [SemanticCategory; 10] = [
    SemanticCategory {
        id: CategoryId::Implementation,
        label: "Implementation",
        description: "Build or change product behavior, features, integrations, or application code.",
    },
    SemanticCategory {
        id: CategoryId::Debugging,
        label: "Debugging",
        description: "Find the cause of incorrect behavior and fix a defect or failure.",
    },
    SemanticCategory {
        id: CategoryId::Research,
        label: "Research",
        description: "Investigate a topic, codebase, or options where the main outcome is understanding.",
    },
    SemanticCategory {
        id: CategoryId::Documentation,
        label: "Documentation",
        description: "Create or update technical explanations, guides, READMEs, or API documentation.",
    },
    SemanticCategory {
        id: CategoryId::ReviewRefactoring,
        label: "Review & refactoring",
        description: "Assess or restructure existing code to improve quality without intentionally changing behavior.",
    },
    SemanticCategory {
        id: CategoryId::Testing,
        label: "Testing",
        description: "Create, maintain, or run tests where verification is the main goal.",
    },
    SemanticCategory {
        id: CategoryId::Planning,
        label: "Planning",
        description: "Define requirements, architecture, or an implementation approach before making changes.",
    },
    SemanticCategory {
        id: CategoryId::Operations,
        label: "Operations",
        description: "Set up or operate environments, builds, CI/CD, releases, deployments, infrastructure, or dependencies.",
    },
    SemanticCategory {
        id: CategoryId::Content,
        label: "Content",
        description: "Create or edit user-facing text or other non-code material that is not technical documentation.",
    },
    SemanticCategory {
        id: CategoryId::Unknown,
        label: "Unknown",
        description: "No supported purpose is clear or dominant from the available session evidence.",
    },
];

pub fn classifier_instructions(repair: bool) -> String {
    let retry = if repair {
        "The previous classifier response was invalid. "
    } else {
        ""
    };
    let categories = SEMANTIC_CATEGORIES
        .iter()
        .map(|category| format!("- {}: {}", category.id.as_str(), category.description))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{retry}Classify this coding-agent session by the user's primary goal, not by isolated tool calls or supporting steps. Choose exactly one category.\n\
         {categories}\n\
         Prefer debugging over implementation when a defect or failure drives the work. Choose testing only when verification itself is the main outcome. Choose research for understanding and planning for a proposed approach. Choose unknown only when the evidence is insufficient, materially mixed, or outside the taxonomy.\n\
         Return only one JSON object with category and confidence from 0 to 1. Do not use Markdown and do not quote or summarize the input."
    )
}

pub fn batch_classifier_instructions() -> String {
    let categories = SEMANTIC_CATEGORIES
        .iter()
        .map(|category| format!("- {}: {}", category.id.as_str(), category.description))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Classify each numbered coding-agent turn by the user's primary goal, not by isolated tool calls. Choose exactly one category per item.\n\
         {categories}\n\
         Prefer debugging when a defect drives the work. Choose testing only when verification is the main outcome. Editing by itself is not implementation. Choose unknown when evidence is insufficient.\n\
         Return only JSON as {{\"results\":[{{\"index\":0,\"category\":\"research\",\"confidence\":0.8}}]}}. Include every input index once, in input order. Do not quote or summarize input text."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn taxonomy_has_ten_unique_categories_and_an_unknown_fallback() {
        assert_eq!(SEMANTIC_CATEGORIES.len(), 10);
        let ids = SEMANTIC_CATEGORIES
            .iter()
            .map(|category| category.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), SEMANTIC_CATEGORIES.len());
        assert!(ids.contains(CategoryId::Unknown.as_str()));
    }

    #[test]
    fn classifier_instructions_define_every_category() {
        let prompt = classifier_instructions(false);
        for category in SEMANTIC_CATEGORIES {
            assert!(prompt.contains(&format!("- {}:", category.id.as_str())));
            assert!(prompt.contains(category.description));
        }
        assert!(prompt.contains("primary goal"));
    }
}

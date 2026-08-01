import { semanticCategories, semanticTaxonomyVersion } from "@/lib/semantic-categories";

export function CategoryGuide() {
  return (
    <details className="panel category-guide" id="category-guide">
      <summary>
        <span className="category-guide-title">How categories work</span>
        <span className="category-guide-summary">10 categories · one primary purpose per session</span>
      </summary>
      <div className="category-guide-body">
        <p>
          Metrune classifies the user&apos;s main goal for the whole session. Supporting work does not
          receive a separate category, and mixed sessions are not split. Taxonomy {semanticTaxonomyVersion}.
        </p>
        <dl className="category-grid">
          {semanticCategories.map(category => (
            <div key={category.id}>
              <dt>{category.label}</dt>
              <dd>{category.description}</dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}

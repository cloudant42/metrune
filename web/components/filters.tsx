import type { Facets, PageParams } from "@/lib/api";
import { label } from "@/lib/format";

const ranges = [
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
  { value: "90", label: "Last 90 days" },
];

const workflowSignals = ["read", "searched", "edited", "tests_run", "tests_failed", "planned", "delegated", "git_used", "built", "deployed"];

export function FilterBar({ params, facets }: { params: PageParams; facets: Facets }) {
  return (
    <form className="filter-bar" aria-label="Filters">
      <label>
        <span>Date range</span>
        <select name="range" defaultValue={params.range ?? "30"}>
          {ranges.map(range => <option key={range.value} value={range.value}>{range.label}</option>)}
        </select>
      </label>
      <FacetSelect name="team" title="Team" all="All teams" value={params.team} options={facets.teams} />
      <FacetSelect name="project" title="Project" all="All projects" value={params.project} options={facets.projects} />
      <FacetSelect name="category" title="Category" all="All categories" value={params.category} options={facets.categories} display={label} />
      <FacetSelect name="client" title="Client" all="All clients" value={params.client} options={facets.clients} />
      <FacetSelect name="status" title="Semantic status" all="Any status" value={params.status} options={facets.statuses} display={label} />
      <FacetSelect name="workflow" title="Workflow" all="Any workflow" value={params.workflow} options={workflowSignals} display={label} />
      <div className="filter-actions">
        <button type="submit" className="btn">Apply</button>
        <a className="btn ghost" href="?">Reset</a>
      </div>
    </form>
  );
}

function FacetSelect({ name, title, all, value, options, display }: { name: string; title: string; all: string; value?: string; options: string[]; display?: (value: string) => string }) {
  const show = display ?? ((entry: string) => entry);
  return (
    <label>
      <span>{title}</span>
      <select name={name} defaultValue={value ?? ""}>
        <option value="">{all}</option>
        {options.map(option => <option key={option} value={option}>{show(option)}</option>)}
      </select>
    </label>
  );
}

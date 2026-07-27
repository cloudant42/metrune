export default function Loading() {
  return <main className="loading-shell" aria-busy="true" aria-label="Loading dashboard">
    <div className="loading-heading" />
    <div className="loading-grid">{Array.from({ length: 4 }, (_, index) => <div className="loading-card" key={index} />)}</div>
    <div className="loading-chart" />
  </main>;
}

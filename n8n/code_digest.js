// n8n Code node - "Hunt digest"  (mode: Run Once for All Items)
// Input : response of GET /api/hunts/run-all  { hunts:[{id,name,hits}], total_hits }
const res = $input.first().json;
const hunts = Array.isArray(res.hunts) ? res.hunts : [];
const withHits = hunts.filter(h => h.hits > 0);
const lines = withHits.map(h => `- ${h.id} ${h.name}: ${h.hits} lead(s)`);
return [{
  json: {
    subject: `NilePay SOC hunt digest: ${withHits.length}/${hunts.length} hunts have leads`,
    total_hits: res.total_hits ?? 0,
    body: lines.length ? lines.join('\n') : 'No hunt leads in this run.',
    generated_at: new Date().toISOString(),
  },
}];

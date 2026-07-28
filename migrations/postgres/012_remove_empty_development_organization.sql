-- Development creates its sample organization at API startup. Remove the
-- migration-era placeholder only when it has never acquired real state. This
-- makes a fresh production database start with operator-owned identity while
-- preserving every upgraded installation that used the original row.
DELETE FROM organizations o
WHERE o.id = '00000000-0000-0000-0000-000000000001'
  AND o.name = 'Acme Engineering'
  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.organization_id = o.id)
  AND NOT EXISTS (
    SELECT 1 FROM organization_memberships m WHERE m.organization_id = o.id
  )
  AND NOT EXISTS (SELECT 1 FROM installations i WHERE i.organization_id = o.id)
  AND NOT EXISTS (SELECT 1 FROM dashboard_tokens d WHERE d.organization_id = o.id)
  AND NOT EXISTS (SELECT 1 FROM enrollment_tokens e WHERE e.organization_id = o.id)
  AND NOT EXISTS (SELECT 1 FROM provider_credentials p WHERE p.organization_id = o.id);

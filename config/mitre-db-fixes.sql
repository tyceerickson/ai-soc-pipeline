-- mitre-db-fixes.sql
-- Purpose: Re-apply the T1078 tactic-scope fix after any Wazuh upgrade
--          that regenerates /var/ossec/var/db/mitre.db.
--
-- HOW RESOLUTION WORKS (important for reproducibility):
--   analysisd resolves <mitre><id>T1078</id></mitre> via the `reference` table:
--     SELECT id FROM reference WHERE external_id='T1078' AND source='mitre-attack'
--     → STIX UUID: attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81
--   It then joins phase + tactic to get tactic names for that UUID.
--   The `alias` table is for software/group names, NOT technique IDs.
--   Do NOT edit `reference` — only `phase` rows need to change.
--
-- Why: In MITRE ATT&CK v14+, T1078 (Valid Accounts) maps to four tactics:
--   Defense Evasion, Persistence, Privilege Escalation, Initial Access.
--   Rule 100112 (cowrie.login.success) should emit ONLY:
--     Credential Access (from T1110) + Initial Access (from T1078).
--   Defense Evasion/Persistence/PrivEsc belong on post-login COMMAND rules
--   (100150-100163), not on the login event itself.
--
-- To re-apply after a Wazuh upgrade:
--   sudo sqlite3 /var/ossec/var/db/mitre.db < /opt/wazuh-soc/rule-backups/mitre-db-fixes.sql
--   sudo systemctl restart wazuh-manager
--   echo '{"data":{"honeypot":"cowrie","eventid":"cowrie.login.success","username":"root","password":"x","src_ip":"1.2.3.4"}}' \
--     | sudo /var/ossec/bin/wazuh-logtest
--   # Verify: mitre.tactic should be ['Credential Access', 'Initial Access'] only

DELETE FROM phase
WHERE tech_id = 'attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81'
  AND tactic_id IN (
    'x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a',
    'x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92',
    'x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd'
  );

-- Verify after running:
-- SELECT tac.name FROM phase p JOIN tactic tac ON p.tactic_id = tac.id
--  WHERE p.tech_id = 'attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81';
-- Expected result: one row → "Initial Access"

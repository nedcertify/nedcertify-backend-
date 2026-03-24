# Configuration Polygon

1. Déploie le contrat `AfricaDiplomaRegistry` sur Polygon Amoy.
2. Autorise le wallet institutionnel via `setInstitutionAuthorization(address,bool)`.
3. Renseigne dans `.env` :
   - `BLOCKCHAIN_MODE=polygon`
   - `POLYGON_RPC_URL`
   - `POLYGON_PRIVATE_KEY`
   - `POLYGON_CONTRACT_ADDRESS`
4. Redémarre l’API.
5. Toute nouvelle certification poussera automatiquement son hash vers Polygon.
6. Pour retraiter les erreurs : `npm run anchor:pending -- 50`
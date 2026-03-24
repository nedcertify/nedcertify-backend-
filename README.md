# Backend privé avec ancrage Polygon automatique

## Nouvelles capacités
- login + endpoint `GET /api/v1/auth/me`
- route `GET /api/v1/audit`
- certification avec statut blockchain `PENDING | SUBMITTING | ANCHORED | FAILED`
- push automatique du hash vers Polygon juste après la certification
- script de reprise pour hashes en attente ou en erreur

## Variables blockchain
Consulter `.env.example`.

## Démarrage
```bash
npm install
cp .env.example .env
npm run prisma:generate
npm run prisma:migrate
npm run prisma:seed
npm run dev
```

## Reprise manuelle des hashes
```bash
npm run anchor:pending -- 50
```

## Flux
1. upload du PDF
2. hash SHA-256
3. coffre-fort objet privé
4. création diplôme + audit
5. ancrage automatique sur Polygon
6. mise à jour du tx hash
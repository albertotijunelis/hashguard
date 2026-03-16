# HashGuard — Stripe Production Checklist

## Pré-requisitos

- [ ] VPS rodando com o "Em Breve" landing page acessível em `https://hashguard.org`
- [ ] Certificado SSL válido (Let's Encrypt via Certbot)
- [ ] Email `contact@hashguard.org` funcionando

## 1. Ativar Stripe Production

1. Acesse [Stripe Dashboard](https://dashboard.stripe.com/settings/account)
2. Em **Business settings → Account details**:
   - Company name: `HashGuard`
   - Website: `https://hashguard.org`
   - Description: `Malware research and analysis platform`
   - Category: `Software as a Service (SaaS)`
3. Complete a verificação de identidade se solicitado
4. Em **Developers → API keys**, copie:
   - `sk_live_...` → coloque em `.env.production` como `STRIPE_SECRET_KEY`
   - `pk_live_...` → coloque em `.env.production` como `STRIPE_PUBLISHABLE_KEY`

## 2. Criar Produtos e Preços no Stripe

```bash
# Pro Plan - $29/mês
stripe products create --name="HashGuard Pro" --description="500 analyses/day, REST API, STIX export"
stripe prices create --product=prod_XXX --currency=usd --unit-amount=2900 --recurring[interval]=month

# Team Plan - $99/mês
stripe products create --name="HashGuard Team" --description="5000 analyses/day, 10 users, webhooks, SOC integrations"
stripe prices create --product=prod_YYY --currency=usd --unit-amount=9900 --recurring[interval]=month
```

3. Copie os Price IDs para `.env.production`:
   - `STRIPE_PRICE_PRO=price_live_...`
   - `STRIPE_PRICE_TEAM=price_live_...`

## 3. Configurar Webhook

1. Em **Developers → Webhooks**, clique "Add endpoint"
2. URL: `https://hashguard.org/api/stripe/webhook`
3. Events a escutar:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Copie o **Webhook signing secret** (`whsec_...`) → `.env.production` como `STRIPE_WEBHOOK_SECRET`

## 4. Atualizar .env.production

```env
STRIPE_SECRET_KEY=sk_live_CHANGE_ME
STRIPE_PUBLISHABLE_KEY=pk_live_CHANGE_ME
STRIPE_WEBHOOK_SECRET=whsec_CHANGE_ME
STRIPE_PRICE_PRO=price_live_CHANGE_ME
STRIPE_PRICE_TEAM=price_live_CHANGE_ME
```

## 5. Testar em Produção

```bash
# Verificar webhook connectivity
curl -s https://hashguard.org/api/stripe/webhook | head

# Testar checkout (com cartão de teste 4242 4242 4242 4242)
# Stripe permite testes mesmo com chaves live se o cartão for de teste
```

## 6. Remover "Em Breve"

Quando estiver pronto para lançar:

```bash
# No .env.production, mude:
HASHGUARD_COMING_SOON=0

# Reinicie o stack:
docker compose -f docker-compose.production.yml restart api
```

## Timeline Sugerida

| Semana | Ação |
|--------|------|
| 1 | VPS + S3 + "Em Breve" + SSL |
| 1-2 | Stripe production keys + webhook |
| 1-4 | Ingest contínuo → 200K samples |
| 4 | `HASHGUARD_COMING_SOON=0` → Launch |

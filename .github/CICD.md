# CI/CD Pipeline Setup

## Overview
Automated testing and deployment pipeline using GitHub Actions.

## Workflows

### 1. CI Workflow (`.github/workflows/ci.yml`)
Runs on every pull request and push to `main`.

**Jobs:**
- **Test Workers**
  - Lint code
  - Type check
  - Run tests
  - Build bundle
  
- **Test Frontend**
  - Lint code
  - Type check
  - Build application

### 2. Deploy Staging (`.github/workflows/deploy-staging.yml`)
Automatically deploys to staging environment on push to `main`.

**Jobs:**
- **Deploy Workers to Staging**
  - Build workers
  - Deploy to Cloudflare Workers (staging environment)

## Required Secrets

Add these secrets to your GitHub repository settings:

1. `CLOUDFLARE_API_TOKEN` - Cloudflare API token with Workers deploy permissions
2. `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID

### How to Get Secrets:

**Cloudflare API Token:**
1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Create token with "Edit Cloudflare Workers" template
3. Copy the token

**Cloudflare Account ID:**
1. Go to Workers & Pages dashboard
2. Copy the Account ID from the right sidebar

## Local Scripts

```bash
# Run tests in CI mode (single run, no watch)
pnpm --filter @board-app/workers test:ci

# Type check
pnpm --filter @board-app/workers typecheck

# Lint
pnpm --filter @board-app/workers lint
```

## Branch Protection

Recommended branch protection rules for `main`:

- ✅ Require pull request before merging
- ✅ Require status checks to pass
  - `Test Workers`
  - `Test Frontend`
- ✅ Require branches to be up to date

## Deployment Environments

- **Staging**: Auto-deployed on merge to `main`
- **Production**: Manual deployment (add workflow when ready)

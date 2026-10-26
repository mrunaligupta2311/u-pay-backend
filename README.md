# U-Pay Backend

Initial backend API foundation for U-Pay.

## Requirements
- Node.js 22+
- pnpm

## Setup
1. Run `pnpm install`.
2. Copy `.env.example` to `.env`.
3. Run `pnpm dev`.

## Endpoints
- `GET /` — API information
- `GET /api/health` — health status

## Scripts
- `pnpm dev` — development server
- `pnpm start` — production server
- `pnpm test` — run tests

## Scope
This is an initial API scaffold. Database-backed accounts, authentication,
OTP verification, wallet ledger, and payment-provider integration are
not implemented yet. This is not a production-ready financial service.
